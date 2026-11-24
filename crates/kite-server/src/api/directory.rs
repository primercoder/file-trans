use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use rusqlite::OptionalExtension as _;
use serde::Serialize;

use crate::{
    api::{ApiError, auth::bearer},
    state::AppState,
};

#[derive(Serialize)]
pub struct DeviceDto {
    pub device_id: String,
    pub name: String,
    pub online: bool,
    pub last_seen: i64,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceDto>>, ApiError> {
    bearer(&state, &headers).await?;
    let devices = {
        let connection = state.db.0.lock().await;
        let mut statement = connection
            .prepare("SELECT device_id,name,last_seen FROM devices ORDER BY device_id")?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let online = state.online.lock().await;
    let now = std::time::Instant::now();
    Ok(Json(
        devices
            .into_iter()
            .map(|(device_id, name, last_seen)| DeviceDto {
                online: online
                    .get(&device_id)
                    .is_some_and(|at| now.duration_since(*at) < state.online_grace),
                device_id,
                name,
                last_seen,
            })
            .collect(),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DeviceDto>, ApiError> {
    bearer(&state, &headers).await?;
    let device = state
        .db
        .0
        .lock()
        .await
        .query_row(
            "SELECT device_id,name,last_seen FROM devices WHERE device_id = ?1",
            [&device_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    let online = state
        .online
        .lock()
        .await
        .get(&device.0)
        .is_some_and(|at| at.elapsed() < state.online_grace);
    Ok(Json(DeviceDto {
        device_id: device.0,
        name: device.1,
        online,
        last_seen: device.2,
    }))
}
