use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use rusqlite::{OptionalExtension as _, params};
use serde::{Deserialize, Serialize};

use crate::{
    api::{ApiError, auth::bearer, mailbox::enqueue, parse_json, token, unix_time},
    state::AppState,
};

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub members: Vec<String>,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub device_id: String,
}

#[derive(Deserialize)]
pub struct GroupSendRequest {
    pub payload: String,
    pub ts: i64,
}

#[derive(Serialize)]
pub struct MemberDto {
    pub device_id: String,
    pub name: String,
    pub role: String,
}

#[derive(Serialize)]
pub struct GroupDto {
    pub group_id: String,
    pub name: String,
    pub owner: String,
    pub members: Vec<MemberDto>,
}

fn group_dto(state_conn: &rusqlite::Connection, group_id: &str) -> Result<GroupDto, ApiError> {
    let (name, owner) = state_conn
        .query_row(
            "SELECT name,owner FROM groups WHERE group_id=?1",
            [group_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    let mut statement = state_conn.prepare(
        "SELECT gm.device_id, d.name, gm.role FROM group_members gm
         JOIN devices d ON d.device_id = gm.device_id
         WHERE gm.group_id=?1 ORDER BY gm.role DESC, gm.device_id",
    )?;
    let members = statement
        .query_map([group_id], |row| {
            Ok(MemberDto {
                device_id: row.get(0)?,
                name: row.get(1)?,
                role: row.get(2)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(GroupDto {
        group_id: group_id.to_owned(),
        name,
        owner,
        members,
    })
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<CreateGroupRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<GroupDto>, ApiError> {
    let owner = bearer(&state, &headers).await?;
    let request: CreateGroupRequest = parse_json(body)?;
    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError::invalid("group name must be 1-64 characters"));
    }
    let mut members: Vec<String> = request
        .members
        .into_iter()
        .filter(|member| member != &owner)
        .collect();
    members.sort();
    members.dedup();
    if members.len() > 128 {
        return Err(ApiError::invalid("group supports at most 128 other members"));
    }
    let group_id = token()?;
    let created_at = unix_time()?;
    {
        let connection = state.db.0.lock().await;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO groups(group_id,name,owner,created_at) VALUES(?1,?2,?3,?4)",
            params![group_id, name, owner, created_at],
        )?;
        transaction.execute(
            "INSERT INTO group_members(group_id,device_id,role) VALUES(?1,?2,'owner')",
            params![group_id, owner],
        )?;
        for member in &members {
            let exists = transaction
                .query_row("SELECT 1 FROM devices WHERE device_id=?1", [member], |_| Ok(()))
                .optional()?
                .is_some();
            if !exists {
                return Err(ApiError::not_found());
            }
            transaction.execute(
                "INSERT INTO group_members(group_id,device_id,role) VALUES(?1,?2,'member')",
                params![group_id, member],
            )?;
        }
        transaction.commit()?;
        Ok(Json(group_dto(&connection, &group_id)?))
    }
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<GroupDto>>, ApiError> {
    let device = bearer(&state, &headers).await?;
    let connection = state.db.0.lock().await;
    let ids: Vec<String> = connection
        .prepare(
            "SELECT g.group_id FROM groups g
             JOIN group_members gm ON gm.group_id = g.group_id
             WHERE gm.device_id=?1 ORDER BY g.created_at DESC",
        )?
        .query_map([&device], |row| row.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut groups = Vec::with_capacity(ids.len());
    for id in ids {
        groups.push(group_dto(&connection, &id)?);
    }
    Ok(Json(groups))
}

pub async fn add_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    body: Result<Json<AddMemberRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<GroupDto>, ApiError> {
    let device = bearer(&state, &headers).await?;
    let request: AddMemberRequest = parse_json(body)?;
    {
        let connection = state.db.0.lock().await;
        let owner: String = connection
            .query_row("SELECT owner FROM groups WHERE group_id=?1", [&group_id], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        if owner != device {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "forbidden",
                "only the group owner can add members",
            ));
        }
        let exists = connection
            .query_row(
                "SELECT 1 FROM devices WHERE device_id=?1",
                [&request.device_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            return Err(ApiError::not_found());
        }
        connection.execute(
            "INSERT OR IGNORE INTO group_members(group_id,device_id,role) VALUES(?1,?2,'member')",
            params![group_id, request.device_id],
        )?;
        Ok(Json(group_dto(&connection, &group_id)?))
    }
}

pub async fn send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    body: Result<Json<GroupSendRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let sender = bearer(&state, &headers).await?;
    let request: GroupSendRequest = parse_json(body)?;
    let members: Vec<String> = {
        let connection = state.db.0.lock().await;
        let member = connection
            .query_row(
                "SELECT 1 FROM group_members WHERE group_id=?1 AND device_id=?2",
                params![group_id, sender],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !member {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "forbidden",
                "sender is not a group member",
            ));
        }
        connection
            .prepare("SELECT device_id FROM group_members WHERE group_id=?1 AND device_id<>?2")?
            .query_map(params![group_id, sender], |row| row.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut delivered = 0_usize;
    for member in members {
        enqueue(
            &state,
            sender.clone(),
            member,
            "group_msg".to_owned(),
            &request.payload,
            request.ts,
            None,
            Some(&group_id),
        )
        .await?;
        delivered += 1;
    }
    Ok(Json(serde_json::json!({"delivered": delivered})))
}

