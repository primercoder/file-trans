use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    api::{ApiError, auth::bearer, mailbox::MAX_PAYLOAD, parse_json},
    state::AppState,
};

#[derive(Deserialize)]
pub struct InitRequest {
    pub size: u64,
    pub chunks: u32,
}

pub async fn init(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<InitRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let owner = bearer(&state, &headers).await?;
    let request = parse_json(body)?;
    let upload = state
        .files
        .create(&state, &owner, request.size, request.chunks)
        .await?;
    Ok(Json(json!({
        "file_id": upload.file_id,
        "upload_id": upload.upload_id,
    })))
}

pub async fn upload_chunk(
    State(state): State<AppState>,
    Path((upload_id, index)): Path<(String, u32)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let owner = bearer(&state, &headers).await?;
    if body.len() > MAX_PAYLOAD {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "chunk exceeds 256 KiB",
        ));
    }
    state
        .files
        .put_chunk(&state, &owner, &upload_id, index, &body)
        .await?;
    Ok(StatusCode::OK)
}

pub async fn status(
    State(state): State<AppState>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let owner = bearer(&state, &headers).await?;
    let (received, status) = state
        .files
        .received_chunks(&state, &owner, &upload_id)
        .await?;
    Ok(Json(json!({"received": received, "status": status})))
}

pub async fn complete(
    State(state): State<AppState>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let owner = bearer(&state, &headers).await?;
    let file_id = state.files.complete(&state, &owner, &upload_id).await?;
    Ok(Json(json!({"file_id": file_id, "status": "ready"})))
}

pub async fn metadata(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<crate::filestore::Metadata>, ApiError> {
    let device_id = bearer(&state, &headers).await?;
    state
        .files
        .authorize_download(&state, &file_id, &device_id)
        .await?;
    Ok(Json(state.files.metadata(&state, &file_id).await?))
}

pub async fn download_chunk(
    State(state): State<AppState>,
    Path((file_id, index)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let device_id = bearer(&state, &headers).await?;
    state
        .files
        .authorize_download(&state, &file_id, &device_id)
        .await?;
    let bytes = state.files.read_chunk(&state, &file_id, index).await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

pub async fn ack_download(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let device_id = bearer(&state, &headers).await?;
    state
        .files
        .acknowledge_download(&state, &file_id, &device_id)
        .await?;
    Ok(Json(json!({"status": "downloaded"})))
}
