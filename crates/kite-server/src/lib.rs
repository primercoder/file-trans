use std::path::Path;

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post, put},
};
use serde_json::json;

use crate::{db::Db, state::AppState};

pub mod api;
pub mod config;
pub mod db;
pub mod filestore;
pub mod state;
pub mod tls;

/// Builds the versioned API against an initialized SQLite database.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/stats", get(api::stats::get))
        .route("/api/v1/register", post(api::auth::register))
        .route("/api/v1/auth/challenge", post(api::auth::challenge))
        .route("/api/v1/auth/verify", post(api::auth::verify))
        .route("/api/v1/devices", get(api::directory::list))
        .route("/api/v1/devices/{device_id}", get(api::directory::get))
        .route("/api/v1/bundles/opks", put(api::bundles::upload_opks))
        .route("/api/v1/bundles/{device_id}", get(api::bundles::get_bundle))
        .route("/api/v1/send", post(api::mailbox::send))
        .route("/api/v1/sync", get(api::mailbox::sync))
        .route("/api/v1/ack", post(api::mailbox::ack))
        .route("/api/v1/groups", post(api::groups::create).get(api::groups::list))
        .route("/api/v1/groups/{group_id}/members", post(api::groups::add_member))
        .route("/api/v1/groups/{group_id}/send", post(api::groups::send))
        .route("/api/v1/files/init", post(api::files::init))
        .route(
            "/api/v1/files/{upload_id}/chunk/{index}",
            put(api::files::upload_chunk).get(api::files::download_chunk),
        )
        .route("/api/v1/files/{upload_id}/status", get(api::files::status))
        .route(
            "/api/v1/files/{upload_id}/complete",
            post(api::files::complete),
        )
        .route("/api/v1/files/{file_id}/meta", get(api::files::metadata))
        .route(
            "/api/v1/files/{file_id}/ack-download",
            post(api::files::ack_download),
        )
        .route("/api/v1/pair/request", post(api::pairing::request))
        .route("/api/v1/pair/respond", post(api::pairing::respond))
        .with_state(state)
}

/// Plaintext by design: container orchestrators use TCP/HTTP health probes.
/// Only healthz is exposed here; authenticated API routes remain TLS-only.
pub fn health_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .with_state(state)
}

/// Installs the process-wide rustls provider used by reqwest and axum-server.
pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub async fn router_with_db(path: &Path) -> Result<Router, Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    Ok(router(AppState::new(Db::open(path)?)))
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_s": state.started.elapsed().as_secs(),
    }))
}
