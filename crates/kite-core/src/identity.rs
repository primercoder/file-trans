use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

/// An Ed25519 identity used by a Kite device.
#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Generates a new identity using the operating system's secure random source.
    pub fn generate() -> Self {
        let mut secret = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut secret)
            .expect("operating system randomness must be available");
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    /// Restores an identity from a PKCS#8 private key in PEM format.
    pub fn from_private(pem: &str) -> Result<Self, ed25519_dalek::pkcs8::Error> {
        Ok(Self {
            signing_key: SigningKey::from_pkcs8_pem(pem)?,
        })
    }

    /// Serializes the private key as a PKCS#8 PEM document with LF line endings.
    ///
    /// This is the inverse of [`Identity::from_private`]; restoring the document
    /// preserves both the Ed25519 key pair and the derived device ID.
    pub fn private_pem(&self) -> String {
        self.signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("serializing an Ed25519 private key cannot fail")
            .to_string()
    }

    /// Serializes the public key as a PEM-encoded SubjectPublicKeyInfo document.
    pub fn public_pem(&self) -> String {
        self.verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("serializing an Ed25519 public key cannot fail")
    }

    /// Returns the device ID: lowercase hex of the first 16 bytes of SHA-256(public key).
    pub fn device_id(&self) -> String {
        let digest = Sha256::digest(self.verifying_key().as_bytes());
        hex::encode(&digest[..16])
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

    #[test]
    fn rfc_8032_ed25519_test_1() {
        let secret =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let expected_public =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let expected_signature = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .unwrap();

        let signing_key = SigningKey::from_bytes(&secret.try_into().unwrap());
        let verifying_key = VerifyingKey::from_bytes(&expected_public.try_into().unwrap()).unwrap();
        let signature: Signature = signing_key.sign(b"");

        assert_eq!(signing_key.verifying_key(), verifying_key);
        assert_eq!(signature.to_bytes().as_slice(), expected_signature);
        verifying_key.verify_strict(b"", &signature).unwrap();
    }
}
