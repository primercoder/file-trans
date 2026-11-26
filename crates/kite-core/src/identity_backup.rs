//! Passphrase-encrypted, offline identity and ratchet-session backups.
//!
//! V1 layout: `KITE-BACKUP-V1` (14 bytes) || salt (16) || nonce (12) ||
//! ChaCha20-Poly1305 ciphertext. The magic includes the version; there is no
//! separate version byte. Private keys occur only in the authenticated payload.
//!
//! V1 always uses the fixed Argon2id parameters below. They are also recorded
//! in the encrypted JSON for information and future evolution, but cannot be
//! consulted before deriving the KEK. V2 may move parameters to an authenticated
//! plaintext header extension. Import requires a fresh store and never registers
//! with the server: that is a post-import UI decision. An existing registration
//! token is restored.
//!
//! Backups have single-active-device semantics: after import, the old device must
//! not be used concurrently against the same peers, or the Double Ratchet forks.
//! Retire the old device's store after migration. Pending file offers
//! (undownloaded files) and in-flight uploads are NOT migrated; download pending
//! files before migration.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use rand::{TryRngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::{
    ApiClient, CryptoError, Engine, EngineError, Identity, Result, Store,
    store::{BackupIdentityState, BackupSession},
};

const MAGIC: &[u8; 14] = b"KITE-BACKUP-V1";
const HEADER_LEN: usize = MAGIC.len() + 16 + 12;
const TAG_LEN: usize = 16;
const DOMAIN: &[u8] = b"kite-identity-backup-v1";
const M_COST_KIB: u32 = 19 * 1024;
const T_COST: u32 = 2;
const P_COST: u32 = 1;

#[derive(Serialize, Deserialize)]
struct KdfParameters {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    identity_pem: String,
    device_name: Option<String>,
    sessions: Vec<BackupSessionPayload>,
    known_peers: Vec<String>,
    token: Option<String>,
    spk_private_b64: String,
    opks_b64: String,
    kdf: KdfParameters,
}

#[derive(Serialize, Deserialize)]
struct BackupSessionPayload {
    peer_device_id: String,
    session_state_b64: String,
    status: String,
}

impl Engine {
    /// Export identity, paired sessions and known peers without any network I/O.
    ///
    /// Pending file offers (undownloaded files) and in-flight uploads are not
    /// migrated. Download pending files before migration.
    ///
    /// Backups have single-active-device semantics: after import, do not use the
    /// old device concurrently against the same peers, or the Double Ratchet
    /// forks. Retire the old device's store after migration.
    pub fn export_identity(&self, passphrase: &str) -> Result<Vec<u8>> {
        let (state, sessions) = self.store.backup()?;
        let known_peers = sessions
            .iter()
            .map(|session| session.peer.clone())
            .collect();
        let payload = BackupPayload {
            identity_pem: state.private_pem,
            device_name: state.name,
            sessions: sessions
                .into_iter()
                .map(|session| BackupSessionPayload {
                    peer_device_id: session.peer,
                    session_state_b64: B64.encode(session.state),
                    status: session.status,
                })
                .collect(),
            known_peers,
            token: state.token,
            spk_private_b64: B64.encode(state.spk_private),
            opks_b64: B64.encode(bincode::serialize(&state.opks)?),
            kdf: KdfParameters {
                m_cost_kib: M_COST_KIB,
                t_cost: T_COST,
                p_cost: P_COST,
            },
        };
        seal(passphrase, &serde_json::to_vec(&payload)?)
    }

    /// Restore into a fresh store; an existing identity or sessions are rejected.
    /// No registration or other network I/O occurs: re-registration is a UI choice.
    /// Pending file offers and in-flight uploads are not restored; download pending
    /// files before migration.
    ///
    /// Backups have single-active-device semantics: after import, do not use the
    /// old device concurrently against the same peers, or the Double Ratchet
    /// forks. Retire the old device's store after migration.
    pub fn import_identity(
        store_path: impl AsRef<Path>,
        base_url: &str,
        server_fingerprint: &str,
        passphrase: &str,
        blob: &[u8],
    ) -> Result<Self> {
        if blob.len() < HEADER_LEN + TAG_LEN {
            return Err(EngineError::BackupTruncated);
        }
        if &blob[..MAGIC.len()] != MAGIC {
            return Err(EngineError::BackupBadFormat(
                "unsupported magic or version".into(),
            ));
        }
        let salt = &blob[MAGIC.len()..MAGIC.len() + 16];
        let nonce = &blob[MAGIC.len() + 16..HEADER_LEN];
        let key = derive_key(passphrase, salt)?;
        let plaintext = ChaCha20Poly1305::new(Key::from_slice(&key))
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &blob[HEADER_LEN..],
                    aad: DOMAIN,
                },
            )
            .map_err(|_| EngineError::BackupAuthentication)?;
        let payload: BackupPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| EngineError::BackupBadFormat("malformed encrypted JSON payload".into()))?;
        let identity = Identity::from_private(&payload.identity_pem)
            .map_err(|_| EngineError::BackupBadFormat("malformed identity PEM".into()))?;
        let spk_private = B64
            .decode(&payload.spk_private_b64)
            .map_err(|_| EngineError::BackupBadFormat("invalid SPK encoding".into()))?
            .try_into()
            .map_err(|_| EngineError::BackupBadFormat("invalid SPK length".into()))?;
        let opks = bincode::deserialize(
            &B64.decode(&payload.opks_b64)
                .map_err(|_| EngineError::BackupBadFormat("invalid OPK encoding".into()))?,
        )
        .map_err(|_| EngineError::BackupBadFormat("malformed OPK state".into()))?;
        let sessions = payload
            .sessions
            .into_iter()
            .map(|session| {
                Ok(BackupSession {
                    peer: session.peer_device_id,
                    state: B64.decode(&session.session_state_b64).map_err(|_| {
                        EngineError::BackupBadFormat("invalid session encoding".into())
                    })?,
                    status: session.status,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let state = BackupIdentityState {
            private_pem: payload.identity_pem,
            token: payload.token,
            spk_private,
            name: payload.device_name,
            opks,
        };
        let store = Store::restore_backup(store_path, &state, &sessions)?;
        let device_id = identity.device_id();
        Ok(Self::from_backup_parts(
            store,
            ApiClient::new(base_url, Some(server_fingerprint))?,
            identity,
            device_id,
            state.name,
            state.token,
            state.spk_private,
        ))
    }
}

fn seal(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    let key = derive_key(passphrase, &salt)?;
    let ciphertext = ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: DOMAIN,
            },
        )
        .map_err(|_| EngineError::Protocol("identity backup encryption failed".into()))?;
    let mut blob = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, Some(32))
        .map_err(|error| EngineError::Configuration(error.to_string()))?;
    let mut key = [0_u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| EngineError::Configuration(error.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_malformed_json_is_bad_format() {
        let blob = seal("secret", b"not JSON").unwrap();
        let temp = tempfile::tempdir().unwrap();
        let error = Engine::import_identity(
            temp.path().join("restored.db"),
            "https://localhost",
            "00".repeat(32).as_str(),
            "secret",
            &blob,
        )
        .err()
        .unwrap();
        assert!(matches!(error, EngineError::BackupBadFormat(_)));
    }
}
