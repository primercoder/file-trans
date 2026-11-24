use std::time::{Duration, Instant};

use axum::{Json, extract::State, http::HeaderMap};
use ed25519_dalek::VerifyingKey;
use rusqlite::{OptionalExtension as _, params};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::{
    api::{
        ApiError, TokenResponse, decode_base64, decode_signature, parse_json, token, token_hash,
        unix_time,
    },
    state::AppState,
};

#[derive(Deserialize)]
pub struct OpkInput {
    pub id: u32,
    pub key: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub device_id: String,
    pub ik_pub: String,
    pub name: String,
    pub hw_hash: String,
    pub spk: String,
    pub spk_sig: String,
    pub opks: Vec<OpkInput>,
    pub sig: String,
}

/// Registration signs exactly `b"register||" || device_id || b"||" || name`.
/// `device_id` and `name` are UTF-8; the Ed25519 signature itself is lowercase hex.
pub async fn register(
    State(state): State<AppState>,
    body: Result<Json<RegisterRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<TokenResponse>, ApiError> {
    let request = parse_json(body)?;
    validate_device_id(&request.device_id)?;
    if request.name.is_empty() || request.name.len() > 256 {
        return Err(ApiError::invalid("name must contain 1 to 256 UTF-8 bytes"));
    }
    let ik = decode_base64::<32>(&request.ik_pub, "ik_pub")?;
    {
        let connection = state.db.0.lock().await;
        let existing: Option<Vec<u8>> = connection
            .query_row(
                "SELECT ik_pub FROM devices WHERE device_id = ?1",
                [&request.device_id],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_some_and(|old| old != ik) {
            return Err(ApiError::conflict(
                "device_id is registered with a different public key",
            ));
        }
    }
    let spk = decode_base64::<32>(&request.spk, "spk")?;
    let spk_sig = decode_base64::<64>(&request.spk_sig, "spk_sig")?;
    let verifying_key =
        VerifyingKey::from_bytes(&ik).map_err(|_| ApiError::invalid("invalid ik_pub"))?;
    let message = format!("register||{}||{}", request.device_id, request.name);
    verifying_key
        .verify_strict(message.as_bytes(), &decode_signature(&request.sig)?)
        .map_err(|_| ApiError::unauthorized("invalid registration signature"))?;

    let mut opks = Vec::with_capacity(request.opks.len());
    for opk in &request.opks {
        opks.push((opk.id, decode_base64::<32>(&opk.key, "opks.key")?.to_vec()));
    }
    let token = token()?;
    let hash = token_hash(&token);
    let now = unix_time()?;
    let connection = state.db.0.lock().await;
    let transaction = connection.unchecked_transaction()?;
    let existing: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT ik_pub FROM devices WHERE device_id = ?1",
            [&request.device_id],
            |row| row.get(0),
        )
        .optional()?;
    if existing.is_some_and(|old| old != ik) {
        return Err(ApiError::conflict(
            "device_id is registered with a different public key",
        ));
    }
    let expected_id = hex::encode(&Sha256::digest(ik)[..16]);
    if request.device_id != expected_id {
        return Err(ApiError::invalid("device_id does not match ik_pub"));
    }
    transaction.execute(
        "INSERT INTO devices(device_id,name,ik_pub,spk,spk_sig,hw_hash,token_hash,last_seen)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(device_id) DO UPDATE SET name=excluded.name,spk=excluded.spk,
         spk_sig=excluded.spk_sig,hw_hash=excluded.hw_hash,token_hash=excluded.token_hash,last_seen=excluded.last_seen",
        params![request.device_id, request.name, ik.as_slice(), spk, spk_sig, request.hw_hash, hash, now],
    )?;
    // Re-registration appends/replaces submitted OPKs without revoking other pending keys.
    for (id, key) in opks {
        transaction.execute(
            "INSERT INTO opk_pool(owner_id,opk_id,key) VALUES(?1,?2,?3)
             ON CONFLICT(owner_id,opk_id) DO UPDATE SET key=excluded.key",
            params![request.device_id, id, key],
        )?;
    }
    transaction.commit()?;
    Ok(Json(TokenResponse {
        token,
        expires_at: 0,
    }))
}

fn validate_device_id(id: &str) -> Result<(), ApiError> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b.is_ascii_digit())
    {
        return Err(ApiError::invalid(
            "device_id must be 32 lowercase hexadecimal characters",
        ));
    }
    if id.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ApiError::invalid("device_id must be lowercase"));
    }
    Ok(())
}

pub async fn bearer(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| ApiError::unauthorized("invalid bearer token"))?;
    let device_id = state
        .db
        .0
        .lock()
        .await
        .query_row(
            "SELECT device_id FROM devices WHERE token_hash = ?1",
            [token_hash(token)],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| ApiError::unauthorized("invalid bearer token"))?;
    Ok(device_id)
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub device_id: String,
}

pub async fn challenge(
    State(state): State<AppState>,
    body: Result<Json<ChallengeRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let request = parse_json(body)?;
    let exists = state
        .db
        .0
        .lock()
        .await
        .query_row(
            "SELECT 1 FROM devices WHERE device_id = ?1",
            [&request.device_id],
            |_| Ok(()),
        )
        .optional()?;
    if exists.is_none() {
        return Err(ApiError::not_found());
    }
    let nonce = token()?;
    state.pending_challenges.lock().await.insert(
        request.device_id,
        (nonce.clone(), Instant::now() + Duration::from_secs(300)),
    );
    Ok(Json(serde_json::json!({"nonce": nonce})))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub device_id: String,
    pub nonce: String,
    pub sig: String,
}

/// Challenge responses sign exactly `b"nonce_text||" || device_id`, both UTF-8.
/// `nonce_text` is the 64-character lowercase hex nonce returned by `/auth/challenge`.
pub async fn verify(
    State(state): State<AppState>,
    body: Result<Json<VerifyRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<TokenResponse>, ApiError> {
    let request = parse_json(body)?;
    let pending = state
        .pending_challenges
        .lock()
        .await
        .remove(&request.device_id);
    let Some((nonce, expires)) = pending else {
        return Err(ApiError::unauthorized("no pending challenge"));
    };
    if expires < Instant::now() || nonce != request.nonce {
        return Err(ApiError::unauthorized(
            "challenge expired or does not match",
        ));
    }
    let ik: Vec<u8> = state
        .db
        .0
        .lock()
        .await
        .query_row(
            "SELECT ik_pub FROM devices WHERE device_id = ?1",
            [&request.device_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    let ik: [u8; 32] = ik
        .try_into()
        .map_err(|_| ApiError::internal("invalid stored identity key"))?;
    let key = VerifyingKey::from_bytes(&ik)
        .map_err(|_| ApiError::internal("invalid stored identity key"))?;
    key.verify_strict(
        format!("{nonce}||{}", request.device_id).as_bytes(),
        &decode_signature(&request.sig)?,
    )
    .map_err(|_| ApiError::unauthorized("invalid challenge signature"))?;
    let token = token()?;
    state.db.0.lock().await.execute(
        "UPDATE devices SET token_hash = ?1, last_seen = ?2 WHERE device_id = ?3",
        params![token_hash(&token), unix_time()?, request.device_id],
    )?;
    Ok(Json(TokenResponse {
        token,
        expires_at: 0,
    }))
}
