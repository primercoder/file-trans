//! Double Ratchet sessions established from an X3DH shared secret.
//!
//! The initiator performs the initial DH ratchet step with the responder's
//! ratchet public key. Every message carries the sender's current ratchet key;
//! receiving a new key advances the receiving chain and starts a new sending
//! chain. Message keys are used once and skipped keys are retained to permit
//! out-of-order delivery within a chain.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;

const MAX_SKIPPED_KEYS: usize = 64;
const ROOT_INFO: &[u8] = b"kite-double-ratchet-root-v1";
const CHAIN_INFO: &[u8] = b"kite-double-ratchet-chain-v1";
type SkippedMessageKey = (([u8; 32], u32), [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct RatchetMessage {
    pub ratchet_pub: Option<[u8; 32]>,
    pub header_seq: u32,
    pub prev_chain_len: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone)]
pub struct Session {
    session_ad: Vec<u8>,
    deterministic_kat: bool,
    root_key: [u8; 32],
    own_ratchet: StaticSecret,
    remote_ratchet_pub: Option<[u8; 32]>,
    sending_chain: Option<[u8; 32]>,
    receiving_chain: Option<[u8; 32]>,
    send_seq: u32,
    recv_seq: u32,
    prev_chain_len: u32,
    skipped_keys: BTreeMap<([u8; 32], u32), [u8; 32]>,
}

#[derive(Serialize, Deserialize)]
struct SerializedSession {
    session_ad: Vec<u8>,
    root_key: [u8; 32],
    own_ratchet: [u8; 32],
    remote_ratchet_pub: Option<[u8; 32]>,
    sending_chain: Option<[u8; 32]>,
    receiving_chain: Option<[u8; 32]>,
    send_seq: u32,
    recv_seq: u32,
    prev_chain_len: u32,
    skipped_keys: Vec<SkippedMessageKey>,
}

impl Serialize for Session {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializedSession {
            session_ad: self.session_ad.clone(),
            root_key: self.root_key,
            own_ratchet: self.own_ratchet.to_bytes(),
            remote_ratchet_pub: self.remote_ratchet_pub,
            sending_chain: self.sending_chain,
            receiving_chain: self.receiving_chain,
            send_seq: self.send_seq,
            recv_seq: self.recv_seq,
            prev_chain_len: self.prev_chain_len,
            skipped_keys: self
                .skipped_keys
                .iter()
                .map(|(id, key)| (*id, *key))
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Session {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let state = SerializedSession::deserialize(deserializer)?;
        if state.skipped_keys.len() > MAX_SKIPPED_KEYS {
            return Err(serde::de::Error::custom("too many skipped message keys"));
        }
        let mut skipped_keys = BTreeMap::new();
        for (id, key) in state.skipped_keys {
            if skipped_keys.insert(id, key).is_some() {
                return Err(serde::de::Error::custom("duplicate skipped message key"));
            }
        }
        Ok(Session {
            session_ad: state.session_ad,
            deterministic_kat: false,
            root_key: state.root_key,
            own_ratchet: StaticSecret::from(state.own_ratchet),
            remote_ratchet_pub: state.remote_ratchet_pub,
            sending_chain: state.sending_chain,
            receiving_chain: state.receiving_chain,
            send_seq: state.send_seq,
            recv_seq: state.recv_seq,
            prev_chain_len: state.prev_chain_len,
            skipped_keys,
        })
    }
}

impl Session {
    pub fn init_as_initiator(
        sk: [u8; 32],
        session_ad: Vec<u8>,
        remote_ratchet_pub: [u8; 32],
    ) -> Result<Session, CryptoError> {
        Self::init_as_initiator_with_ratchet(
            sk,
            session_ad,
            remote_ratchet_pub,
            random_ratchet_key()?.to_bytes(),
        )
    }

    /// Deterministic initializer for pinned cross-change protocol vectors.
    pub fn init_as_initiator_with_ratchet(
        sk: [u8; 32],
        session_ad: Vec<u8>,
        remote_ratchet_pub: [u8; 32],
        own_ratchet: [u8; 32],
    ) -> Result<Session, CryptoError> {
        Self::init_with_ratchet(
            sk,
            session_ad,
            remote_ratchet_pub,
            StaticSecret::from(own_ratchet),
        )
    }

    fn init_with_ratchet(
        sk: [u8; 32],
        session_ad: Vec<u8>,
        remote_ratchet_pub: [u8; 32],
        own_ratchet: StaticSecret,
    ) -> Result<Session, CryptoError> {
        let (root_key, sending_chain) =
            derive_root(sk, &own_ratchet, &PublicKey::from(remote_ratchet_pub))?;
        Ok(Session {
            session_ad,
            deterministic_kat: false,
            root_key,
            own_ratchet,
            remote_ratchet_pub: Some(remote_ratchet_pub),
            sending_chain: Some(sending_chain),
            receiving_chain: None,
            send_seq: 0,
            recv_seq: 0,
            prev_chain_len: 0,
            skipped_keys: BTreeMap::new(),
        })
    }

    /// Returns the two Ed25519 identity keys bound into this session, in the
    /// `(initiator, responder)` order used by the session associated data.
    ///
    /// Engines use this to recover the peer identity for safety-number display
    /// without a separate trust store: the binding is authenticated by every
    /// message via the AEAD associated data.
    pub fn identity_binding(&self) -> Option<([u8; 32], [u8; 32])> {
        let bytes: [u8; 64] = self.session_ad.as_slice().try_into().ok()?;
        let mut initiator = [0_u8; 32];
        let mut responder = [0_u8; 32];
        initiator.copy_from_slice(&bytes[..32]);
        responder.copy_from_slice(&bytes[32..]);
        Some((initiator, responder))
    }

    pub fn init_as_responder(
        sk: [u8; 32],
        session_ad: Vec<u8>,
        ratchet_keypair: ([u8; 32], [u8; 32]),
    ) -> Result<Session, CryptoError> {
        let (private, public) = ratchet_keypair;
        let own_ratchet = StaticSecret::from(private);
        if PublicKey::from(&own_ratchet).to_bytes() != public {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Session {
            session_ad,
            deterministic_kat: false,
            root_key: sk,
            own_ratchet,
            remote_ratchet_pub: None,
            sending_chain: None,
            receiving_chain: None,
            send_seq: 0,
            recv_seq: 0,
            prev_chain_len: 0,
            skipped_keys: BTreeMap::new(),
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<RatchetMessage, CryptoError> {
        let mut nonce_bytes = [0_u8; 12];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        self.encrypt_inner(plaintext, ad, nonce_bytes, false)
    }

    /// Deterministic nonce and DH advancement for protocol known-answer tests.
    pub fn enable_deterministic_kat(&mut self) {
        self.deterministic_kat = true;
    }

    pub fn encrypt_with_nonce(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
        nonce_bytes: [u8; 12],
    ) -> Result<RatchetMessage, CryptoError> {
        self.encrypt_inner(plaintext, ad, nonce_bytes, true)
    }

    fn encrypt_inner(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
        nonce_bytes: [u8; 12],
        deterministic: bool,
    ) -> Result<RatchetMessage, CryptoError> {
        if self.sending_chain.is_none() {
            let remote = self.remote_ratchet_pub.ok_or(CryptoError::InvalidMessage)?;
            if self.receiving_chain.is_some() {
                self.own_ratchet = if deterministic {
                    let mut seed = self.own_ratchet.to_bytes().to_vec();
                    seed.extend_from_slice(&nonce_bytes);
                    StaticSecret::from(<[u8; 32]>::from(Sha256::digest(seed)))
                } else {
                    random_ratchet_key()?
                };
            }
            let (root, chain) =
                derive_root(self.root_key, &self.own_ratchet, &PublicKey::from(remote))?;
            self.root_key = root;
            self.sending_chain = Some(chain);
            self.send_seq = 0;
        }

        let chain = self.sending_chain.ok_or(CryptoError::InvalidKey)?;
        let (next_chain, message_key) = derive_message_key(chain)?;
        self.sending_chain = Some(next_chain);
        let header_seq = self.send_seq;
        self.send_seq = self
            .send_seq
            .checked_add(1)
            .ok_or(CryptoError::InvalidKey)?;

        let nonce = Nonce::from(nonce_bytes);
        let ratchet_pub = PublicKey::from(&self.own_ratchet).to_bytes();
        let aad = authenticated_data(
            &self.session_ad,
            ad,
            &ratchet_pub,
            header_seq,
            self.prev_chain_len,
            &nonce_bytes,
        );
        let ciphertext = ChaCha20Poly1305::new(Key::from_slice(&message_key))
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptFailed)?;
        Ok(RatchetMessage {
            ratchet_pub: Some(ratchet_pub),
            header_seq,
            prev_chain_len: self.prev_chain_len,
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    pub fn decrypt(&mut self, msg: &RatchetMessage, ad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ratchet_pub = msg.ratchet_pub.ok_or(CryptoError::InvalidMessage)?;
        let skipped_id = (ratchet_pub, msg.header_seq);
        if let Some(message_key) = self.skipped_keys.get(&skipped_id).copied() {
            let plaintext = decrypt_with_key(message_key, &self.session_ad, msg, ad)?;
            self.skipped_keys.remove(&skipped_id);
            return Ok(plaintext);
        }

        let mut staged = self.clone();
        if staged.remote_ratchet_pub != Some(ratchet_pub) {
            if staged.receiving_chain.is_some() {
                staged.skip_message_keys(msg.prev_chain_len)?;
            }
            staged.dh_ratchet(ratchet_pub)?;
        }
        staged.skip_message_keys(msg.header_seq)?;
        let chain = staged.receiving_chain.ok_or(CryptoError::InvalidMessage)?;
        let (next_chain, message_key) = derive_message_key(chain)?;
        let plaintext = decrypt_with_key(message_key, &staged.session_ad, msg, ad)?;
        // Commit the clone only after AEAD succeeds; forged headers leave self intact.
        *self = staged;
        self.receiving_chain = Some(next_chain);
        self.recv_seq = self
            .recv_seq
            .checked_add(1)
            .ok_or(CryptoError::InvalidKey)?;
        Ok(plaintext)
    }

    fn dh_ratchet(&mut self, remote: [u8; 32]) -> Result<(), CryptoError> {
        let remote_key = PublicKey::from(remote);
        let (root, receiving_chain) = derive_root(self.root_key, &self.own_ratchet, &remote_key)?;
        self.root_key = root;
        self.receiving_chain = Some(receiving_chain);
        self.recv_seq = 0;
        self.prev_chain_len = self.send_seq;
        self.remote_ratchet_pub = Some(remote);
        self.own_ratchet = if self.deterministic_kat {
            let mut seed = self.own_ratchet.to_bytes().to_vec();
            seed.extend_from_slice(&remote);
            StaticSecret::from(<[u8; 32]>::from(Sha256::digest(seed)))
        } else {
            random_ratchet_key()?
        };
        let (root, sending_chain) = derive_root(self.root_key, &self.own_ratchet, &remote_key)?;
        self.root_key = root;
        self.sending_chain = Some(sending_chain);
        self.send_seq = 0;
        Ok(())
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), CryptoError> {
        if until < self.recv_seq {
            return Err(CryptoError::InvalidMessage);
        }
        let skipped = (until - self.recv_seq) as usize;
        if skipped > MAX_SKIPPED_KEYS || self.skipped_keys.len() + skipped > MAX_SKIPPED_KEYS {
            return Err(CryptoError::SkippedLimit);
        }
        let remote = self.remote_ratchet_pub.ok_or(CryptoError::InvalidMessage)?;
        let mut chain = self.receiving_chain.ok_or(CryptoError::InvalidMessage)?;
        for seq in self.recv_seq..until {
            let (next_chain, message_key) = derive_message_key(chain)?;
            self.skipped_keys.insert((remote, seq), message_key);
            chain = next_chain;
        }
        self.receiving_chain = Some(chain);
        self.recv_seq = until;
        Ok(())
    }
}

fn random_ratchet_key() -> Result<StaticSecret, CryptoError> {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok(StaticSecret::from(bytes))
}

fn derive_root(
    root: [u8; 32],
    private: &StaticSecret,
    public: &PublicKey,
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let dh = private.diffie_hellman(public).to_bytes();
    if dh == [0_u8; 32] {
        return Err(CryptoError::ZeroDh);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&root), &dh);
    let mut next_root = [0_u8; 32];
    let mut chain = [0_u8; 32];
    hkdf.expand(ROOT_INFO, &mut next_root)
        .map_err(|_| CryptoError::HkdfLength)?;
    hkdf.expand(&[ROOT_INFO, b" chain"].concat(), &mut chain)
        .map_err(|_| CryptoError::HkdfLength)?;
    Ok((next_root, chain))
}

fn derive_message_key(chain: [u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&chain), CHAIN_INFO);
    let mut next_chain = [0_u8; 32];
    let mut message_key = [0_u8; 32];
    hkdf.expand(b"next", &mut next_chain)
        .map_err(|_| CryptoError::HkdfLength)?;
    hkdf.expand(b"message", &mut message_key)
        .map_err(|_| CryptoError::HkdfLength)?;
    Ok((next_chain, message_key))
}

fn authenticated_data(
    session_ad: &[u8],
    external_ad: &[u8],
    ratchet_pub: &[u8; 32],
    header_seq: u32,
    prev_chain_len: u32,
    nonce: &[u8; 12],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(session_ad.len() + external_ad.len() + 60);
    aad.extend_from_slice(&(session_ad.len() as u64).to_be_bytes());
    aad.extend_from_slice(session_ad);
    aad.extend_from_slice(external_ad);
    aad.extend_from_slice(ratchet_pub);
    aad.extend_from_slice(&header_seq.to_be_bytes());
    aad.extend_from_slice(&prev_chain_len.to_be_bytes());
    aad.extend_from_slice(nonce);
    aad
}

fn decrypt_with_key(
    message_key: [u8; 32],
    session_ad: &[u8],
    msg: &RatchetMessage,
    ad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let ratchet_pub = msg.ratchet_pub.ok_or(CryptoError::InvalidMessage)?;
    let aad = authenticated_data(
        session_ad,
        ad,
        &ratchet_pub,
        msg.header_seq,
        msg.prev_chain_len,
        &msg.nonce,
    );
    ChaCha20Poly1305::new(Key::from_slice(&message_key))
        .decrypt(
            Nonce::from_slice(&msg.nonce),
            Payload {
                msg: &msg.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}
