use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rusqlite::{OptionalExtension as _, params};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        ApiError,
        auth::{OpkInput, bearer},
        decode_base64, parse_json,
    },
    state::AppState,
};

#[derive(Deserialize)]
pub struct UploadOpks {
    pub opks: Vec<OpkInput>,
}

pub async fn upload_opks(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<UploadOpks>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let owner_id = bearer(&state, &headers).await?;
    let request = parse_json(body)?;
    let mut opks = Vec::with_capacity(request.opks.len());
    for opk in request.opks {
        opks.push((opk.id, decode_base64::<32>(&opk.key, "opks.key")?.to_vec()));
    }
    let connection = state.db.0.lock().await;
    let transaction = connection.unchecked_transaction()?;
    for (id, key) in opks {
        transaction.execute(
            "INSERT INTO opk_pool(owner_id,opk_id,key) VALUES(?1,?2,?3)
             ON CONFLICT(owner_id,opk_id) DO UPDATE SET key=excluded.key",
            params![owner_id, id, key],
        )?;
    }
    transaction.commit()?;
    Ok(Json(serde_json::json!({"uploaded": true})))
}

#[derive(Serialize)]
pub struct PreKeyBundleDto {
    pub ik: String,
    pub spk: String,
    pub spk_sig: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opk_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opk: Option<String>,
}

pub async fn get_bundle(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PreKeyBundleDto>, ApiError> {
    bearer(&state, &headers).await?;
    let connection = state.db.0.lock().await;
    // A single transaction makes selection and deletion atomic: no OPK can be issued twice.
    let transaction = connection.unchecked_transaction()?;
    let bundle = transaction
        .query_row(
            "SELECT ik_pub,spk,spk_sig FROM devices WHERE device_id = ?1",
            [&device_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    let opk = transaction
        .query_row(
            "SELECT opk_id,key FROM opk_pool WHERE owner_id = ?1 ORDER BY opk_id LIMIT 1",
            [&device_id],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    if let Some((opk_id, _)) = &opk {
        transaction.execute(
            "DELETE FROM opk_pool WHERE owner_id = ?1 AND opk_id = ?2",
            params![device_id, opk_id],
        )?;
    }
    transaction.commit()?;
    let (opk_id, opk) = opk.unzip();
    Ok(Json(PreKeyBundleDto {
        ik: B64.encode(bundle.0),
        spk: B64.encode(bundle.1),
        spk_sig: B64.encode(bundle.2),
        opk_id,
        opk: opk.map(|key| B64.encode(key)),
    }))
}
