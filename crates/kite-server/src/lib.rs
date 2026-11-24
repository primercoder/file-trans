use std::path::Path;

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post, put},
};
use serde_json::json;

use crate::{db::Db, state::AppState};

pub mod api;
pub mod db;
pub mod state;
pub mod tls;

/// Builds the versioned API against an initialized SQLite database.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/register", post(api::auth::register))
        .route("/api/v1/auth/challenge", post(api::auth::challenge))
        .route("/api/v1/auth/verify", post(api::auth::verify))
        .route("/api/v1/devices", get(api::directory::list))
        .route("/api/v1/devices/{device_id}", get(api::directory::get))
        .route("/api/v1/bundles/opks", put(api::bundles::upload_opks))
        .route("/api/v1/bundles/{device_id}", get(api::bundles::get_bundle))
        .with_state(state)
}

pub async fn router_with_db(path: &Path) -> Result<Router, Box<dyn std::error::Error>> {
    Ok(router(AppState::new(Db::open(path)?)))
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_s": state.started.elapsed().as_secs(),
    }))
}
