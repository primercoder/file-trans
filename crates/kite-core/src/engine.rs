//! High-level client flow: registration, asynchronous pairing, and messaging.
//!
//! Pair requests are base64(JSON `{header, body}`): the plaintext header contains
//! only public X3DH fields (`ik_pub`, `ek_pub`, `used_opk_id`), while `body` is
//! base64(bincode(`RatchetMessage`)) encrypting `{name, challenge, ts}`.
//! Pair responses similarly expose only `accepted`; their encrypted body contains
//! `{challenge, ts}`. Messages are base64(bincode(`RatchetMessage`)). All private
//! pairing content and messages are therefore ciphertext on the server.

use std::path::Path;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher as _, SaltString, rand_core::OsRng as HashOsRng},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rand::{TryRngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    ApiClient, BundleDto, CryptoError, DeviceInfo, EngineError, Identity, IdentityState,
    InitiatorKeys, PreKeyBundle, RatchetMessage, ResponderKeys, Result, Session, Store,
    generate_spk, store::EntryOutcome,
};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum InboxEvent {
    PairRequest { from: String, name: String },
    PairResponse { from: String, accepted: bool },
    Message { from: String, text: String },
}

#[derive(Serialize, Deserialize)]
struct PairRequestWire {
    version: u8,
    ik_pub: String,
    ek_pub: String,
    used_opk_id: Option<u32>,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct PairRequestBody {
    name: String,
    challenge: [u8; 32],
    ts: i64,
}

#[derive(Serialize, Deserialize)]
struct PairResponseWire {
    version: u8,
    accepted: bool,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct PairResponseBody {
    challenge: [u8; 32],
    ts: i64,
}

pub struct Engine {
    store: Store,
    api: ApiClient,
    identity: Identity,
    device_id: String,
    name: Option<String>,
    token: Option<String>,
    spk_private: [u8; 32],
}

impl Engine {
    pub fn open(
        store_path: impl AsRef<Path>,
        base_url: &str,
        server_fingerprint: &str,
    ) -> Result<Self> {
        let store = Store::open(store_path)?;
        let api = ApiClient::new(base_url, server_fingerprint)?;
        let state = store.identity()?;
        let (identity, name, token, spk_private) = if let Some(state) = state {
            (
                Identity::from_private(&state.private_pem)?,
                state.name,
                state.token,
                state.spk_private,
            )
        } else {
            let identity = Identity::generate();
            let (spk_private, _, _) = generate_spk(&identity);
            store.save_identity(&IdentityState {
                private_pem: identity.private_pem(),
                token: None,
                spk_private,
                name: None,
                opks: Vec::new(),
            })?;
            (identity, None, None, spk_private)
        };
        let device_id = identity.device_id();
        Ok(Self {
            store,
            api,
            identity,
            device_id,
            name,
            token,
            spk_private,
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub async fn register(&mut self, name: &str, raw_hw_id: &str) -> Result<()> {
        let device_id = self.device_id().to_owned();
        let salt = SaltString::generate(&mut HashOsRng);
        let hw_hash = Argon2::default()
            .hash_password(raw_hw_id.as_bytes(), &salt)
            .map_err(|error| EngineError::HardwareHash(error.to_string()))?
            .to_string();
        let (spk_private, spk, spk_sig) = generate_spk(&self.identity);
        let mut old_opks = self
            .store
            .identity()?
            .map(|state| state.opks)
            .unwrap_or_default();
        let first_opk_id = old_opks
            .iter()
            .map(|(id, _)| *id)
            .max()
            .map_or(0, |id| id.saturating_add(1));
        let opks: Vec<(u32, [u8; 32])> = (first_opk_id..first_opk_id + 10)
            .map(|id| {
                let mut bytes = [0_u8; 32];
                OsRng
                    .try_fill_bytes(&mut bytes)
                    .map_err(|_| CryptoError::RandomnessUnavailable)?;
                Ok((id, bytes))
            })
            .collect::<std::result::Result<_, CryptoError>>()?;
        let ik_pub = self.identity.ed25519_public_key();
        let sig = self
            .identity
            .sign_bytes(format!("register||{device_id}||{name}").as_bytes());
        let body = serde_json::json!({
            "device_id": device_id,
            "ik_pub": B64.encode(ik_pub),
            "name": name,
            "hw_hash": hw_hash,
            "spk": B64.encode(spk),
            "spk_sig": B64.encode(spk_sig),
            "opks": opks.iter().map(|(id, secret)| {
                let public = PublicKey::from(&StaticSecret::from(*secret)).to_bytes();
                serde_json::json!({"id": id, "key": B64.encode(public)})
            }).collect::<Vec<_>>(),
            "sig": hex::encode(sig),
        });
        // Persist only after server success: a failed registration must leave
        // the previous identity/token/prekeys usable. Re-registering replaces
        // the SPK but deliberately leaves all paired sessions intact.
        // The server keeps only this latest SPK, so an in-flight handshake that
        // fetched the previous SPK can fail; callers may retry with a new bundle.
        let token = self.api.register(body).await?;
        old_opks.extend(opks);
        self.spk_private = spk_private;
        self.name = Some(name.to_owned());
        self.token = Some(token);
        self.store.save_identity(&IdentityState {
            private_pem: self.identity.private_pem(),
            token: self.token.clone(),
            spk_private,
            name: self.name.clone(),
            opks: old_opks,
        })?;
        Ok(())
    }

    pub async fn refresh_devices(&mut self) -> Result<Vec<DeviceInfo>> {
        self.api.devices(&self.token()?).await
    }

    pub async fn start_pairing(&mut self, peer: &str) -> Result<()> {
        let token = self.token()?;
        let dto = self.api.bundle(&token, peer).await?;
        let bundle = decode_bundle(dto)?;
        let x3dh = InitiatorKeys::run(&bundle, &self.identity)?;
        let ad = associated_data(&self.identity.ed25519_public_key(), &bundle.ik_pub);
        let mut session = Session::init_as_initiator(x3dh.shared_secret, ad, bundle.spk)?;
        let challenge = random_bytes()?;
        let name = self
            .name
            .clone()
            .unwrap_or_else(|| self.device_id().to_owned());
        let body = PairRequestBody {
            name: name.clone(),
            challenge,
            ts: unix_time()?,
        };
        let body = session.encrypt(&bincode::serialize(&body)?, &[])?;
        let envelope = PairRequestWire {
            version: 1,
            ik_pub: B64.encode(self.identity.ed25519_public_key()),
            ek_pub: B64.encode(x3dh.ek_pub),
            used_opk_id: x3dh.used_opk_id,
            body: encode(&body)?,
        };
        // Persist before sending so a timeout leaves recoverable pending state.
        // A definite send failure rolls it back; ambiguous timeout reconciliation
        // is post-M1 work (the server may still deliver the request).
        self.store
            .save_session(peer, &bincode::serialize(&session)?, "pending_outgoing")?;
        self.store.save_pending(peer, &name, challenge)?;
        if let Err(error) = self
            .api
            .pair_request(&token, peer, B64.encode(serde_json::to_vec(&envelope)?))
            .await
        {
            if !matches!(&error, EngineError::Http(error) if error.is_timeout()) {
                self.store.rollback_pairing(peer, "pending_outgoing")?;
            }
            return Err(error);
        }
        Ok(())
    }

    pub async fn confirm_pairing(&mut self, peer: &str) -> Result<()> {
        let Some((state, status)) = self.store.session(peer)? else {
            return Err(EngineError::Protocol("no pairing session for peer".into()));
        };
        if status != "pending_accept" {
            return Err(EngineError::Protocol(
                "pairing is not awaiting acceptance".into(),
            ));
        }
        let (_, challenge) = self
            .store
            .pending(peer)?
            .ok_or_else(|| EngineError::Protocol("pairing request is not pending".into()))?;
        let response_body = PairResponseBody {
            challenge,
            ts: unix_time()?,
        };
        let mut session: Session = bincode::deserialize(&state)?;
        let body = session.encrypt(&bincode::serialize(&response_body)?, &[])?;
        let response = PairResponseWire {
            version: 1,
            accepted: true,
            body: encode(&body)?,
        };
        if let Err(error) = self
            .api
            .pair_response(
                &self.token()?,
                peer,
                true,
                B64.encode(serde_json::to_vec(&response)?),
            )
            .await
        {
            if !matches!(&error, EngineError::Http(error) if error.is_timeout()) {
                self.store.rollback_pairing(peer, "pending_accept")?;
            }
            return Err(error);
        }
        self.store
            .save_session(peer, &bincode::serialize(&session)?, "paired")?;
        self.store.remove_pending(peer)?;
        Ok(())
    }

    pub async fn send_message(&mut self, peer: &str, text: &str) -> Result<()> {
        let (state, status) = self
            .store
            .session(peer)?
            .ok_or_else(|| EngineError::Protocol("peer is not paired".into()))?;
        if status != "paired" {
            return Err(EngineError::Protocol(
                "pairing has not been accepted".into(),
            ));
        }
        let mut session: Session = bincode::deserialize(&state)?;
        let ad = session_ad(&session);
        let message = session.encrypt(text.as_bytes(), &ad)?;
        self.store
            .save_session(peer, &bincode::serialize(&session)?, "paired")?;
        self.api
            .send(&self.token()?, peer, "msg", encode(&message)?)
            .await
    }

    pub async fn poll_once(&mut self) -> Result<Vec<InboxEvent>> {
        let token = self.token()?;
        let cursor = self.store.cursor()?;
        if cursor > 0 {
            // Retry cleanup for the previously committed but possibly un-ACKed prefix.
            let _ = self.api.ack(&token, cursor).await;
        }
        let entries = self.api.sync(&token, cursor).await?;
        let mut events = Vec::new();
        let mut latest = None;
        for entry in entries {
            // Poison, replay, stale timestamps and consumed ratchet keys are all
            // durable failures, not reasons to wedge every subsequent entry.
            let outcome = match self.process_entry(&entry) {
                Ok(outcome) => outcome,
                Err(error @ (EngineError::Store(_) | EngineError::Io(_))) => return Err(error),
                Err(_) => EntryOutcome::failed(),
            };
            if let Some(event) = self.store.commit_entry(entry.seq, outcome)? {
                events.push(event);
            }
            latest = Some(entry.seq);
        }
        if let Some(seq) = latest {
            // Every entry through seq has committed locally. ACK is best-effort:
            // an ACK failure must not discard events or committed ratchet state.
            let _ = self.api.ack(&token, seq).await;
        }
        Ok(events)
    }

    fn process_entry(&mut self, entry: &crate::api_client::MailEntry) -> Result<EntryOutcome> {
        match entry.kind.as_str() {
            "pair_req" => self.receive_pair_request(&entry.from, &entry.payload),
            "pair_resp" => self.receive_pair_response(&entry.from, &entry.payload),
            "msg" => self.receive_message(&entry.from, &entry.payload),
            _ => Ok(EntryOutcome::failed()),
        }
    }

    fn receive_pair_response(&self, from: &str, payload: &str) -> Result<EntryOutcome> {
        let response: PairResponseWire = serde_json::from_slice(&B64.decode(payload)?)?;
        if response.version != 1 {
            return Err(EngineError::Protocol("unsupported pair response".into()));
        }
        let Some((state, status)) = self.store.session(from)? else {
            return Err(EngineError::Protocol("response for unknown peer".into()));
        };
        if status != "pending_outgoing" {
            return Err(EngineError::Protocol("unsolicited pair response".into()));
        }
        let Some((_, challenge)) = self.store.pending(from)? else {
            return Err(EngineError::Protocol("unsolicited pair response".into()));
        };
        let body: RatchetMessage = decode(&response.body)?;
        let mut session: Session = bincode::deserialize(&state)?;
        let plaintext = session.decrypt(&body, &[])?;
        let body: PairResponseBody = bincode::deserialize(&plaintext)?;
        check_timestamp(body.ts)?;
        if challenge != body.challenge {
            return Err(EngineError::Protocol(
                "pair response challenge mismatch".into(),
            ));
        }
        Ok(EntryOutcome {
            event: Some(InboxEvent::PairResponse {
                from: from.to_owned(),
                accepted: response.accepted,
            }),
            session: response.accepted.then(|| {
                (
                    from.to_owned(),
                    bincode::serialize(&session).unwrap_or_default(),
                    "paired".into(),
                )
            }),
            remove_session: (!response.accepted).then(|| from.to_owned()),
            remove_pending: Some(from.to_owned()),
            ..EntryOutcome::default()
        })
    }

    fn receive_message(&self, from: &str, payload: &str) -> Result<EntryOutcome> {
        let (state, status) = self
            .store
            .session(from)?
            .ok_or_else(|| EngineError::Protocol("message from unpaired peer".into()))?;
        if status != "paired" {
            return Err(EngineError::Protocol(
                "message before pairing accepted".into(),
            ));
        }
        let mut session: Session = bincode::deserialize(&state)?;
        let ad = session_ad(&session);
        let message: RatchetMessage = decode(payload)?;
        let plaintext = session.decrypt(&message, &ad)?;
        let text = String::from_utf8(plaintext)?;
        Ok(EntryOutcome {
            event: Some(InboxEvent::Message {
                from: from.to_owned(),
                text,
            }),
            session: Some((
                from.to_owned(),
                bincode::serialize(&session)?,
                "paired".into(),
            )),
            ..EntryOutcome::default()
        })
    }

    fn receive_pair_request(&self, from: &str, payload: &str) -> Result<EntryOutcome> {
        let envelope: PairRequestWire = serde_json::from_slice(&B64.decode(payload)?)?;
        if envelope.version != 1 {
            return Err(EngineError::Protocol("unsupported pair request".into()));
        }
        let ik_pub = decode_array(&envelope.ik_pub)?;
        let ek_pub = decode_array(&envelope.ek_pub)?;
        let sender_id = hex::encode(&Sha256::digest(ik_pub)[..16]);
        if sender_id != from {
            return Err(EngineError::Protocol(
                "pair request identity does not match sender".into(),
            ));
        }
        if self.store.session(from)?.is_some()
            || self
                .store
                .handshake_seen(from, &Sha256::digest(ek_pub).into())?
        {
            return Err(EngineError::Protocol(
                "replayed or already-paired request".into(),
            ));
        }
        let opk = match envelope.used_opk_id {
            Some(id) => {
                let identity = self
                    .store
                    .identity()?
                    .ok_or_else(|| EngineError::Protocol("identity is not initialized".into()))?;
                Some(
                    identity
                        .opks
                        .iter()
                        .find(|(key_id, _)| *key_id == id)
                        .map(|(_, secret)| *secret)
                        .ok_or_else(|| {
                            EngineError::Protocol("one-time prekey is no longer available".into())
                        })?,
                )
            }
            None => None,
        };
        let responder = ResponderKeys::run(
            &self.identity,
            &self.spk_private,
            opk.as_ref(),
            &ik_pub,
            &ek_pub,
        )?;
        let private = self.spk_private;
        let ratchet = StaticSecret::from(private);
        let public = PublicKey::from(&ratchet).to_bytes();
        let ad = associated_data(&ik_pub, &self.identity.ed25519_public_key());
        let mut session =
            Session::init_as_responder(responder.shared_secret, ad, (private, public))?;
        let encrypted: RatchetMessage = decode(&envelope.body)?;
        let plaintext = session.decrypt(&encrypted, &[])?;
        let body: PairRequestBody = bincode::deserialize(&plaintext)?;
        check_timestamp(body.ts)?;
        // OPK and replay nonce become durable only after successful authentication.
        Ok(EntryOutcome {
            event: Some(InboxEvent::PairRequest {
                from: from.to_owned(),
                name: body.name.clone(),
            }),
            session: Some((
                from.to_owned(),
                bincode::serialize(&session)?,
                "pending_accept".into(),
            )),
            pending: Some((from.to_owned(), body.name, body.challenge)),
            consume_opk: envelope.used_opk_id,
            handshake_nonce: Some((from.to_owned(), Sha256::digest(ek_pub).into())),
            ..EntryOutcome::default()
        })
    }

    fn token(&self) -> Result<String> {
        self.token
            .clone()
            .ok_or_else(|| EngineError::Protocol("device is not registered".into()))
    }
}

fn decode_bundle(dto: BundleDto) -> Result<PreKeyBundle> {
    Ok(PreKeyBundle {
        ik_pub: decode_array(&dto.ik)?,
        spk: decode_array(&dto.spk)?,
        spk_sig: decode_array(&dto.spk_sig)?,
        opk_id: dto.opk_id,
        opk: dto.opk.as_deref().map(decode_array).transpose()?,
    })
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    B64.decode(value)?
        .try_into()
        .map_err(|_| EngineError::Protocol("incorrect key length".into()))
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    Ok(B64.encode(bincode::serialize(value)?))
}

fn decode<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T> {
    Ok(bincode::deserialize(&B64.decode(value)?)?)
}

fn associated_data(initiator: &[u8; 32], responder: &[u8; 32]) -> Vec<u8> {
    [initiator.as_slice(), responder.as_slice()].concat()
}

fn session_ad(session: &Session) -> Vec<u8> {
    // Ratchet encrypt/decrypt accepts AD separately; the serialized session also
    // authenticates its stored AD internally. Passing the empty external AD keeps
    // this API independent of peer ordering after restoration.
    let _ = session;
    Vec::new()
}

fn random_bytes() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok(bytes)
}

fn check_timestamp(ts: i64) -> Result<()> {
    if (unix_time()? - ts).abs() > 120 {
        return Err(EngineError::Protocol(
            "pairing envelope timestamp outside 120s window".into(),
        ));
    }
    Ok(())
}

fn unix_time() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| EngineError::Configuration(error.to_string()))?
        .as_secs() as i64)
}
