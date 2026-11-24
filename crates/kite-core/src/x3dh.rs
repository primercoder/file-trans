//! X3DH asynchronous key agreement using Ed25519 identities and X25519 prekeys.
//!
//! The input key material is `DH1 || DH2 || DH3 [|| DH4]`. From the initiator's
//! perspective: DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B),
//! DH3 = DH(EK_A, SPK_B), and DH4 = DH(EK_A, OPK_B) when an OPK is present.
//! The shared key is HKDF-SHA256(IKM, salt = empty, info = "kite-x3dh-v1"),
//! with a 32-byte output. The associated data for the subsequent ratchet is
//! `ik_pub_A || ik_pub_B` (64 bytes of raw Ed25519 public keys); X3DH passes
//! these keys through but does not itself encrypt or authenticate ciphertext.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::Identity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    BadSignature,
    ZeroDh,
    InvalidKey,
    HkdfLength,
}

pub struct PreKeyBundle {
    pub ik_pub: [u8; 32],
    pub spk: [u8; 32],
    pub spk_sig: [u8; 64],
    pub opk_id: Option<u32>,
    pub opk: Option<[u8; 32]>,
}

pub struct InitiatorKeys {
    pub shared_secret: [u8; 32],
    pub ek_pub: [u8; 32],
    pub used_opk_id: Option<u32>,
}

pub struct ResponderKeys {
    pub shared_secret: [u8; 32],
}

/// Generates an X25519 signed prekey and signs its raw public key with `ik`.
pub fn generate_spk(ik: &Identity) -> ([u8; 32], [u8; 32], [u8; 64]) {
    let mut secret = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut secret)
        .expect("operating system randomness must be available");
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret).to_bytes();
    (secret.to_bytes(), public, ik.sign_bytes(&public))
}

impl InitiatorKeys {
    pub fn run(bundle: &PreKeyBundle, ik: &Identity) -> Result<Self, CryptoError> {
        let verifying_key =
            VerifyingKey::from_bytes(&bundle.ik_pub).map_err(|_| CryptoError::InvalidKey)?;
        verifying_key
            .verify_strict(&bundle.spk, &Signature::from_bytes(&bundle.spk_sig))
            .map_err(|_| CryptoError::BadSignature)?;

        let ik_x = identity_to_x25519(ik);
        let peer_ik = ed25519_to_x25519(&bundle.ik_pub)?;
        let spk = PublicKey::from(bundle.spk);
        let mut ek_bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut ek_bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        let ek = StaticSecret::from(ek_bytes);
        let ek_pub = PublicKey::from(&ek).to_bytes();

        let dh1 = dh(&ik_x, &spk)?;
        let dh2 = dh(&ek, &peer_ik)?;
        let dh3 = dh(&ek, &spk)?;
        let mut ikm = [0_u8; 128];
        ikm[..32].copy_from_slice(&dh1);
        ikm[32..64].copy_from_slice(&dh2);
        ikm[64..96].copy_from_slice(&dh3);
        let used_opk_id = match (bundle.opk_id, bundle.opk) {
            (Some(id), Some(opk)) => {
                ikm[96..].copy_from_slice(&dh(&ek, &PublicKey::from(opk))?);
                Some(id)
            }
            (None, None) => None,
            _ => return Err(CryptoError::InvalidKey),
        };
        let ikm_len = if used_opk_id.is_some() { 128 } else { 96 };
        Ok(Self {
            shared_secret: derive_sk(&ikm[..ikm_len])?,
            ek_pub,
            used_opk_id,
        })
    }
}

impl ResponderKeys {
    pub fn run(
        ik: &Identity,
        spk_priv: &[u8; 32],
        opk_priv: Option<&[u8; 32]>,
        ik_pub_peer: &[u8; 32],
        ek_pub_peer: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let ik_x = identity_to_x25519(ik);
        let spk = StaticSecret::from(*spk_priv);
        let peer_ik = ed25519_to_x25519(ik_pub_peer)?;
        let peer_ek = PublicKey::from(*ek_pub_peer);
        let dh1 = dh(&spk, &peer_ik)?;
        let dh2 = dh(&ik_x, &peer_ek)?;
        let dh3 = dh(&spk, &peer_ek)?;
        let mut ikm = [0_u8; 128];
        ikm[..32].copy_from_slice(&dh1);
        ikm[32..64].copy_from_slice(&dh2);
        ikm[64..96].copy_from_slice(&dh3);
        let ikm_len = if let Some(opk) = opk_priv {
            ikm[96..].copy_from_slice(&dh(&StaticSecret::from(*opk), &peer_ek)?);
            128
        } else {
            96
        };
        Ok(Self {
            shared_secret: derive_sk(&ikm[..ikm_len])?,
        })
    }
}

fn dh(secret: &StaticSecret, public: &PublicKey) -> Result<[u8; 32], CryptoError> {
    let output = secret.diffie_hellman(public).to_bytes();
    if output == [0_u8; 32] {
        Err(CryptoError::ZeroDh)
    } else {
        Ok(output)
    }
}

fn derive_sk(ikm: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut sk = [0_u8; 32];
    Hkdf::<Sha256>::new(None, ikm)
        .expand(b"kite-x3dh-v1", &mut sk)
        .map_err(|_| CryptoError::HkdfLength)?;
    Ok(sk)
}

fn identity_to_x25519(identity: &Identity) -> StaticSecret {
    let digest = Sha512::digest(identity.signing_key_bytes());
    let mut scalar = [0_u8; 32];
    scalar.copy_from_slice(&digest[..32]);
    StaticSecret::from(scalar)
}

fn ed25519_to_x25519(public: &[u8; 32]) -> Result<PublicKey, CryptoError> {
    let point = CompressedEdwardsY(*public)
        .decompress()
        .ok_or(CryptoError::InvalidKey)?;
    let montgomery = point.to_montgomery();
    if montgomery == MontgomeryPoint([0_u8; 32]) {
        return Err(CryptoError::InvalidKey);
    }
    Ok(PublicKey::from(montgomery.to_bytes()))
}
