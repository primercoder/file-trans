use axum::{Json, extract::State, http::HeaderMap};
use serde::Deserialize;
use serde_json::json;

use crate::{
    api::{ApiError, auth::bearer, mailbox::enqueue, parse_json, unix_time},
    state::AppState,
};

#[derive(Deserialize)]
pub struct PairRequest {
    pub to: String,
    pub payload: String,
}

pub async fn request(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PairRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let from = bearer(&state, &headers).await?;
    let request = parse_json(body)?;
    let seq = enqueue(
        &state,
        from,
        request.to,
        "pair_req".to_owned(),
        &request.payload,
        unix_time()?,
        None,
    )
    .await?;
    Ok(Json(json!({"seq": seq})))
}

#[derive(Deserialize)]
pub struct PairResponse {
    pub to: String,
    pub accept: bool,
    pub payload: String,
}

pub async fn respond(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PairResponse>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let from = bearer(&state, &headers).await?;
    let request = parse_json(body)?;
    // The accept flag is deliberately not interpreted or persisted by the server.
    let _ = request.accept;
    let seq = enqueue(
        &state,
        from,
        request.to,
        "pair_resp".to_owned(),
        &request.payload,
        unix_time()?,
        None,
    )
    .await?;
    Ok(Json(json!({"seq": seq})))
}
