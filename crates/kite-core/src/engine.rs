//! High-level client flow: registration, asynchronous pairing, and messaging.
//!
//! Pair requests are base64(JSON `{header, body}`): the plaintext header contains
//! only public X3DH fields (`ik_pub`, `ek_pub`, `used_opk_id`), while `body` is
//! base64(bincode(`RatchetMessage`)) encrypting `{name, challenge, ts}`.
//! Pair responses similarly expose only `accepted`; their encrypted body contains
//! `{challenge, ts}`. Messages are base64(bincode(`RatchetMessage`)). All private
//! pairing content and messages are therefore ciphertext on the server.

use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rand::{TryRngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    ApiClient, BundleDto, CryptoError, DeviceInfo, EngineError, Identity, IdentityState,
    InitiatorKeys, PreKeyBundle, RatchetMessage, ResponderKeys, Result, Session, Store,
    generate_spk,
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

    pub async fn register(&mut self, name: &str, hw_hash: &str) -> Result<()> {
        let device_id = self.device_id().to_owned();
        let (spk_private, spk, spk_sig) = generate_spk(&self.identity);
        let opks: Vec<(u32, [u8; 32])> = (0..10)
            .map(|id| {
                let mut bytes = [0_u8; 32];
                OsRng
                    .try_fill_bytes(&mut bytes)
                    .map_err(|_| CryptoError::RandomnessUnavailable)?;
                Ok((id, bytes))
            })
            .collect::<std::result::Result<_, CryptoError>>()?;
        self.spk_private = spk_private;
        self.name = Some(name.to_owned());
        self.store.save_identity(&IdentityState {
            private_pem: self.identity.private_pem(),
            token: self.token.clone(),
            spk_private,
            name: self.name.clone(),
            opks: opks.clone(),
        })?;
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
        let token = self.api.register(body).await?;
        self.token = Some(token);
        self.persist_identity()?;
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
        self.api
            .pair_request(&token, peer, B64.encode(serde_json::to_vec(&envelope)?))
            .await?;
        self.store
            .save_session(peer, &bincode::serialize(&session)?, "pending_outgoing")?;
        self.store.save_pending(peer, &name, challenge)?;
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
        self.api
            .pair_response(
                &self.token()?,
                peer,
                true,
                B64.encode(serde_json::to_vec(&response)?),
            )
            .await?;
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
        let entries = self.api.sync(&token, self.store.cursor()?).await?;
        let mut events = Vec::new();
        let mut latest = None;
        for entry in entries {
            match entry.kind.as_str() {
                "pair_req" => events.push(self.receive_pair_request(&entry.from, &entry.payload)?),
                "pair_resp" => {
                    let response: PairResponseWire =
                        serde_json::from_slice(&B64.decode(&entry.payload)?)?;
                    if response.version != 1 {
                        return Err(EngineError::Protocol("unsupported pair response".into()));
                    }
                    let Some((state, status)) = self.store.session(&entry.from)? else {
                        return Err(EngineError::Protocol("response for unknown peer".into()));
                    };
                    if status != "pending_outgoing" {
                        return Err(EngineError::Protocol("unsolicited pair response".into()));
                    }
                    let Some((_, challenge)) = self.store.pending(&entry.from)? else {
                        return Err(EngineError::Protocol("unsolicited pair response".into()));
                    };
                    let body: RatchetMessage = decode(&response.body)?;
                    let mut session: Session = bincode::deserialize(&state)?;
                    let plaintext = session.decrypt(&body, &[])?;
                    let body: PairResponseBody = bincode::deserialize(&plaintext)?;
                    if challenge != body.challenge {
                        return Err(EngineError::Protocol(
                            "pair response challenge mismatch".into(),
                        ));
                    }
                    if response.accepted {
                        self.store.save_session(
                            &entry.from,
                            &bincode::serialize(&session)?,
                            "paired",
                        )?;
                    } else {
                        self.store.remove_session(&entry.from)?;
                    }
                    self.store.remove_pending(&entry.from)?;
                    events.push(InboxEvent::PairResponse {
                        from: entry.from,
                        accepted: response.accepted,
                    });
                }
                "msg" => {
                    let (state, status) = self.store.session(&entry.from)?.ok_or_else(|| {
                        EngineError::Protocol("message from unpaired peer".into())
                    })?;
                    if status != "paired" {
                        return Err(EngineError::Protocol(
                            "message before pairing accepted".into(),
                        ));
                    }
                    let mut session: Session = bincode::deserialize(&state)?;
                    let ad = session_ad(&session);
                    let message: RatchetMessage = decode(&entry.payload)?;
                    let plaintext = session.decrypt(&message, &ad)?;
                    self.store.save_session(
                        &entry.from,
                        &bincode::serialize(&session)?,
                        "paired",
                    )?;
                    events.push(InboxEvent::Message {
                        from: entry.from,
                        text: String::from_utf8(plaintext)?,
                    });
                }
                _ => {}
            }
            latest = Some(entry.seq);
        }
        if let Some(seq) = latest {
            // Never let the server discard an entry before its cursor is durable.
            self.store.set_cursor(seq)?;
            self.api.ack(&token, seq).await?;
        }
        Ok(events)
    }

    fn receive_pair_request(&mut self, from: &str, payload: &str) -> Result<InboxEvent> {
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
        let opk = match envelope.used_opk_id {
            Some(id) => self.store.take_opk(id)?,
            None => None,
        };
        let responder = ResponderKeys::run(
            &self.identity,
            &self.spk_private,
            opk.as_ref(),
            &ik_pub,
            &ek_pub,
        )?;
        // The initiator's first DH ratchet step targets the signed prekey, so
        // the responder must initialize its session with that same key pair.
        let private = self.spk_private;
        let ratchet = StaticSecret::from(private);
        let public = PublicKey::from(&ratchet).to_bytes();
        let ad = associated_data(&ik_pub, &self.identity.ed25519_public_key());
        let mut session =
            Session::init_as_responder(responder.shared_secret, ad, (private, public))?;
        let encrypted: RatchetMessage = decode(&envelope.body)?;
        let plaintext = session.decrypt(&encrypted, &[])?;
        let body: PairRequestBody = bincode::deserialize(&plaintext)?;
        self.store
            .save_session(from, &bincode::serialize(&session)?, "pending_accept")?;
        self.store.save_pending(from, &body.name, body.challenge)?;
        Ok(InboxEvent::PairRequest {
            from: from.to_owned(),
            name: body.name,
        })
    }

    fn token(&self) -> Result<String> {
        self.token
            .clone()
            .ok_or_else(|| EngineError::Protocol("device is not registered".into()))
    }

    fn persist_identity(&self) -> Result<()> {
        let old = self
            .store
            .identity()?
            .ok_or_else(|| EngineError::Protocol("identity is not initialized".into()))?;
        self.store.save_identity(&IdentityState {
            private_pem: self.identity.private_pem(),
            token: self.token.clone(),
            spk_private: self.spk_private,
            name: self.name.clone(),
            opks: old.opks,
        })?;
        Ok(())
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

fn unix_time() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| EngineError::Configuration(error.to_string()))?
        .as_secs() as i64)
}
