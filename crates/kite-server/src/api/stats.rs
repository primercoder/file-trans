use axum::{Json, extract::State, http::HeaderMap};
use serde::Serialize;

use crate::{
    api::{ApiError, auth::bearer},
    state::AppState,
};

#[derive(Serialize)]
pub struct StatsResponse {
    pub devices: u64,
    pub mailboxes_pending: u64,
    /// M2 will enforce storage quotas and report actual usage; M1's contract is always zero.
    pub storage_used: u64,
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatsResponse>, ApiError> {
    bearer(&state, &headers).await?;
    let connection = state.db.0.lock().await;
    let devices = connection.query_row("SELECT COUNT(*) FROM devices", [], |row| {
        row.get::<_, u64>(0)
    })?;
    // A successful ACK deletes rows, so every remaining mailbox row is pending.
    let mailboxes_pending = connection.query_row("SELECT COUNT(*) FROM mailboxes", [], |row| {
        row.get::<_, u64>(0)
    })?;
    Ok(Json(StatsResponse {
        devices,
        mailboxes_pending,
        storage_used: 0,
    }))
}
