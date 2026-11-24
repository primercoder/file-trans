//! Double Ratchet sessions established from an X3DH shared secret.
//!
//! The initiator performs the initial DH ratchet step with the responder's
//! ratchet public key. Every message carries the sender's current ratchet key;
//! receiving a new key advances the receiving chain and starts a new sending
//! chain. Message keys are used once and skipped keys are retained to permit
//! out-of-order delivery within a chain.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;

const MAX_SKIPPED_KEYS: usize = 64;
const ROOT_INFO: &[u8] = b"kite-double-ratchet-root-v1";
const CHAIN_INFO: &[u8] = b"kite-double-ratchet-chain-v1";

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct RatchetMessage {
    pub ratchet_pub: Option<[u8; 32]>,
    pub header_seq: u32,
    pub prev_chain_len: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub struct Session {
    session_ad: Vec<u8>,
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

impl Session {
    pub fn init_as_initiator(
        sk: [u8; 32],
        session_ad: Vec<u8>,
        remote_ratchet_pub: [u8; 32],
    ) -> Result<Session, CryptoError> {
        let own_ratchet = random_ratchet_key()?;
        let (root_key, sending_chain) =
            derive_root(sk, &own_ratchet, &PublicKey::from(remote_ratchet_pub))?;
        Ok(Session {
            session_ad,
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
        if self.sending_chain.is_none() {
            let remote = self.remote_ratchet_pub.ok_or(CryptoError::InvalidMessage)?;
            self.own_ratchet = random_ratchet_key()?;
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

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut nonce_bytes = [0_u8; 12];
        nonce_bytes.copy_from_slice(&nonce);
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
            .map_err(|_| CryptoError::DecryptFailed)?;
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

        if self.remote_ratchet_pub != Some(ratchet_pub) {
            if self.receiving_chain.is_some() {
                self.skip_message_keys(msg.prev_chain_len)?;
            }
            self.dh_ratchet(ratchet_pub)?;
        }
        self.skip_message_keys(msg.header_seq)?;
        let chain = self.receiving_chain.ok_or(CryptoError::InvalidMessage)?;
        let (next_chain, message_key) = derive_message_key(chain)?;
        let plaintext = decrypt_with_key(message_key, &self.session_ad, msg, ad)?;
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
        self.own_ratchet = random_ratchet_key()?;
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
