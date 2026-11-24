use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rusqlite::{OptionalExtension as _, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Notify;

use crate::{
    api::{ApiError, auth::bearer, parse_json, unix_time},
    state::AppState,
};

pub const MAX_PAYLOAD: usize = 256 * 1024;

#[derive(Deserialize)]
pub struct SendRequest {
    pub to: String,
    pub kind: String,
    pub payload: String,
    pub ts: i64,
}

#[derive(Serialize)]
pub struct Entry {
    pub seq: i64,
    pub from: String,
    pub kind: String,
    pub payload: String,
    pub ts: i64,
}

/// Persists an entry and assigns its owner-local sequence in the same transaction.
/// Notification happens only after commit, so every wakeup observes durable data.
pub async fn enqueue(
    state: &AppState,
    from: String,
    to: String,
    kind: String,
    encoded_payload: &str,
    ts: i64,
) -> Result<i64, ApiError> {
    let payload = B64
        .decode(encoded_payload)
        .map_err(|_| ApiError::invalid("payload must be standard base64"))?;
    if payload.len() > MAX_PAYLOAD {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "payload exceeds 256 KiB",
        ));
    }
    if ts.abs_diff(unix_time()?) > 120 {
        return Err(ApiError::invalid(
            "ts differs from server time by more than 120 seconds",
        ));
    }
    let seq = {
        let connection = state.db.0.lock().await;
        let transaction = connection.unchecked_transaction()?;
        let exists = transaction
            .query_row("SELECT 1 FROM devices WHERE device_id = ?1", [&to], |_| {
                Ok(())
            })
            .optional()?;
        if exists.is_none() {
            return Err(ApiError::not_found());
        }
        let seq: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM mailboxes WHERE owner_id = ?1",
            [&to],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO mailboxes(owner_id,seq,from_id,kind,payload,ts) VALUES(?1,?2,?3,?4,?5,?6)",
            params![to, seq, from, kind, payload, ts],
        )?;
        transaction.commit()?;
        seq
    };
    notifier(state, &to).await.notify_waiters();
    Ok(seq)
}

async fn notifier(state: &AppState, owner: &str) -> Arc<Notify> {
    state
        .notifications
        .lock()
        .await
        .entry(owner.to_owned())
        .or_insert_with(|| Arc::new(Notify::new()))
        .clone()
}

pub async fn send(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<SendRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let from = bearer(&state, &headers).await?;
    let request = parse_json(body)?;
    let seq = enqueue(
        &state,
        from,
        request.to,
        request.kind,
        &request.payload,
        request.ts,
    )
    .await?;
    Ok(Json(json!({"seq": seq})))
}

#[derive(Deserialize)]
pub struct SyncQuery {
    #[serde(default)]
    pub since: i64,
    #[serde(default)]
    pub wait: Option<u8>,
}

pub async fn sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SyncQuery>,
) -> Result<Json<Vec<Entry>>, ApiError> {
    let owner = bearer(&state, &headers).await?;
    let notification = notifier(&state, &owner).await;
    let notified = notification.notified();
    tokio::pin!(notified);
    // Register before reading, closing the read-then-wait notification race.
    notified.as_mut().enable();
    let mut entries = read_entries(&state, &owner, query.since).await?;
    if entries.is_empty() && query.wait == Some(1) {
        let _ = tokio::time::timeout(Duration::from_secs(25), notified).await;
        entries = read_entries(&state, &owner, query.since).await?;
    }
    Ok(Json(entries))
}

async fn read_entries(state: &AppState, owner: &str, since: i64) -> Result<Vec<Entry>, ApiError> {
    let connection = state.db.0.lock().await;
    let mut statement = connection.prepare(
        "SELECT seq,from_id,kind,payload,ts FROM mailboxes
         WHERE owner_id = ?1 AND seq > ?2 ORDER BY seq ASC",
    )?;
    let rows = statement.query_map(params![owner, since], |row| {
        Ok(Entry {
            seq: row.get(0)?,
            from: row.get(1)?,
            kind: row.get(2)?,
            payload: B64.encode(row.get::<_, Vec<u8>>(3)?),
            ts: row.get(4)?,
        })
    })?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

#[derive(Deserialize)]
pub struct AckRequest {
    pub until_seq: i64,
}

pub async fn ack(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<AckRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let owner = bearer(&state, &headers).await?;
    let request = parse_json(body)?;
    let deleted = state.db.0.lock().await.execute(
        "DELETE FROM mailboxes WHERE owner_id = ?1 AND seq <= ?2",
        params![owner, request.until_seq],
    )?;
    Ok(Json(json!({"deleted": deleted})))
}
