//! Platform-agnostic protocol, framing and crypto primitives for Kite.

mod api_client;
mod device_name;
mod engine;
mod file_crypto;
mod identity;
mod ratchet;
mod store;
mod x3dh;

pub use api_client::ApiClient;
pub use device_name::HwInfo;
pub use engine::InboxEvent;
pub use file_crypto::{
    ChunkCipher, EncryptedChunk, FileCryptoError, FileHeader, FileKey, decrypt_file, encrypt_file,
};
pub use identity::Identity;
pub use ratchet::{RatchetMessage, Session};
pub use store::Store;
pub use x3dh::{CryptoError, InitiatorKeys, PreKeyBundle, ResponderKeys, generate_spk};

use serde::{Deserialize, Serialize};

use api_client::BundleDto;
pub use engine::Engine;
use store::IdentityState;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct DeviceInfo {
    pub device_id: String,
    pub name: String,
    pub online: bool,
    pub last_seen: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned {status}: {message}")]
    Server {
        status: reqwest::StatusCode,
        message: String,
    },
    #[error("local store failed: {0}")]
    Store(#[from] rusqlite::Error),
    #[error("local I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("hardware identifier hashing failed: {0}")]
    HardwareHash(String),
    #[error("serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("identity failed: {0}")]
    Identity(#[from] ed25519_dalek::pkcs8::Error),
    #[error("cryptography failed: {0:?}")]
    Crypto(CryptoError),
    #[error("invalid UTF-8 message: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("integer conversion failed: {0}")]
    Integer(#[from] std::num::ParseIntError),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<CryptoError> for EngineError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

pub type Result<T> = std::result::Result<T, EngineError>;

/// Version of the `kite-core` crate, sourced from its manifest.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
