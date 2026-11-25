use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::json;

pub mod auth;
pub mod bundles;
pub mod directory;
pub mod files;
pub mod mailbox;
pub mod pairing;
pub mod stats;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_input", message)
    }

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "device not found")
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    pub fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!(%error, "internal server error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal server error",
        )
    }

    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(value: rusqlite::Error) -> Self {
        Self::internal(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error": {"code": self.code, "message": self.message}})),
        )
            .into_response()
    }
}

pub fn parse_json<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    body.map(|Json(value)| value)
        .map_err(|error| ApiError::invalid(error.body_text()))
}

pub fn decode_base64<const N: usize>(value: &str, field: &str) -> Result<[u8; N], ApiError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| ApiError::invalid(format!("{field} must be standard base64")))?;
    bytes
        .try_into()
        .map_err(|_| ApiError::invalid(format!("{field} must decode to {N} bytes")))
}

pub fn decode_signature(value: &str) -> Result<ed25519_dalek::Signature, ApiError> {
    let bytes = hex::decode(value).map_err(|_| ApiError::invalid("sig must be hex"))?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| ApiError::invalid("sig must be 64 bytes"))?;
    Ok(ed25519_dalek::Signature::from_bytes(&bytes))
}

pub fn token() -> Result<String, ApiError> {
    use rand::{TryRngCore as _, rngs::OsRng};
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| ApiError::internal(format!("OS randomness unavailable: {error}")))?;
    Ok(hex::encode(bytes))
}

pub fn token_hash(token: &str) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn unix_time() -> Result<i64, ApiError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| ApiError::internal(format!("system clock before Unix epoch: {error}")))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| ApiError::internal("system time exceeds i64 seconds"))
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    /// M1 bearer tokens do not expire; zero is an explicit placeholder.
    pub expires_at: u64,
}
