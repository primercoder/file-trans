use std::path::{Path, PathBuf};

use axum::http::StatusCode;
use rusqlite::{Connection, OptionalExtension as _, Transaction, params};
use serde::Serialize;
use tokio::fs;

use crate::{
    api::{ApiError, token, unix_time},
    state::AppState,
};

#[derive(Clone)]
pub struct FileStore {
    root: PathBuf,
    max_storage_bytes: u64,
}

struct EvictionCandidate {
    id: String,
    size: i64,
    downloaded: bool,
}

pub struct Upload {
    pub file_id: String,
    pub upload_id: String,
    pub chunks: u32,
}

#[derive(Serialize)]
pub struct Metadata {
    pub size: u64,
    pub chunks: u32,
}

fn oldest_eviction_candidate(
    connection: &Connection,
    downloaded: bool,
) -> Result<Option<EvictionCandidate>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT file_id,size FROM files
             WHERE (?1 AND EXISTS(
                 SELECT 1 FROM file_refs
                 WHERE file_refs.file_id=files.file_id AND downloaded_at IS NOT NULL
             )) OR (NOT ?1 AND NOT EXISTS(
                 SELECT 1 FROM file_refs
                 WHERE file_refs.file_id=files.file_id AND downloaded_at IS NOT NULL
             ))
             ORDER BY created_at ASC, file_id ASC LIMIT 1",
            [downloaded],
            |row| {
                Ok(EvictionCandidate {
                    id: row.get(0)?,
                    size: row.get(1)?,
                    downloaded,
                })
            },
        )
        .optional()
}

fn enqueue_eviction_notices(
    transaction: &Transaction<'_>,
    file_id: &str,
    notified_recipients: &mut Vec<String>,
) -> Result<(), ApiError> {
    // Mailboxes store raw bytes; sync performs the base64 envelope encoding.
    let payload =
        serde_json::to_vec(&serde_json::json!({"file_id": file_id})).map_err(ApiError::internal)?;
    let ts = unix_time()?;
    let recipients = {
        let mut statement = transaction.prepare(
            "SELECT device_id FROM files_recipients WHERE file_id=?1 ORDER BY device_id",
        )?;
        statement
            .query_map([file_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for recipient in recipients {
        let seq: i64 = transaction
            .query_row(
                "SELECT COALESCE(last_seq,0)+1 FROM owner_seq WHERE owner_id=?1",
                [&recipient],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(1);
        transaction.execute(
            "INSERT INTO owner_seq(owner_id,last_seq) VALUES(?1,?2)
             ON CONFLICT(owner_id) DO UPDATE SET last_seq=excluded.last_seq",
            params![recipient, seq],
        )?;
        transaction.execute(
            "INSERT INTO mailboxes(owner_id,seq,from_id,kind,payload,ts)
             VALUES(?1,?2,'server','file_evicted',?3,?4)",
            params![recipient, seq, payload, ts],
        )?;
        notified_recipients.push(recipient);
    }
    Ok(())
}

struct CleanupDebt {
    file_id: String,
    directory: PathBuf,
}

async fn remove_chunk_directory(directory: &Path) -> std::io::Result<()> {
    match fs::remove_dir_all(directory).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

async fn cleanup_debt(state: &AppState, file_id: &str, directory: &Path) {
    match remove_chunk_directory(directory).await {
        Ok(()) => {
            if let Err(error) = state
                .db
                .0
                .lock()
                .await
                .execute("DELETE FROM pending_cleanup WHERE file_id=?1", [file_id])
            {
                tracing::warn!(file_id, %error, "failed to clear completed cleanup debt");
            }
        }
        Err(error) => {
            tracing::warn!(file_id, path = %directory.display(), %error, "file cleanup deferred");
        }
    }
}

/// Best-effort recovery for cleanup debt committed before a crash or I/O failure.
/// Reconciliation never prevents the server from starting; debt remains durable for retry.
pub async fn reconcile_pending_cleanup(state: &AppState) {
    let debts = {
        let connection = state.db.0.lock().await;
        let result = (|| -> Result<Vec<CleanupDebt>, rusqlite::Error> {
            let mut statement = connection
                .prepare("SELECT file_id,dir FROM pending_cleanup ORDER BY created_at,file_id")?;
            let rows = statement.query_map([], |row| {
                Ok(CleanupDebt {
                    file_id: row.get(0)?,
                    directory: PathBuf::from(row.get::<_, String>(1)?),
                })
            })?;
            rows.collect()
        })();
        match result {
            Ok(debts) => debts,
            Err(error) => {
                tracing::warn!(%error, "failed to read pending cleanup debt");
                return;
            }
        }
    };
    for debt in debts {
        cleanup_debt(state, &debt.file_id, &debt.directory).await;
    }
}

impl FileStore {
    pub fn new(data_dir: PathBuf, max_storage_bytes: u64) -> Self {
        Self {
            root: data_dir.join("files"),
            max_storage_bytes,
        }
    }

    /// Counts bytes for every live upload, including incomplete and unreceived files.
    pub async fn storage_used(state: &AppState) -> Result<u64, ApiError> {
        let used = state.db.0.lock().await.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM files",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(used as u64)
    }

    pub async fn create(
        &self,
        state: &AppState,
        owner: &str,
        size: u64,
        chunks: u32,
    ) -> Result<Upload, ApiError> {
        if chunks == 0 {
            return Err(ApiError::invalid("chunks must be greater than zero"));
        }
        if size > self.max_storage_bytes {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "file exceeds the server storage quota",
            ));
        }
        let size = i64::try_from(size).map_err(|_| ApiError::invalid("size is too large"))?;
        let upload = Upload {
            file_id: token()?,
            upload_id: token()?,
            chunks,
        };
        let (cleanup_debts, notified_recipients) = {
            let connection = state.db.0.lock().await;
            let transaction = connection.unchecked_transaction()?;
            let mut used: i64 =
                transaction.query_row("SELECT COALESCE(SUM(size), 0) FROM files", [], |row| {
                    row.get(0)
                })?;
            let max_storage_bytes = i64::try_from(self.max_storage_bytes)
                .map_err(|_| ApiError::internal("storage quota exceeds i64"))?;
            let mut cleanup_debts = Vec::new();
            let mut notified_recipients = Vec::new();
            while max_storage_bytes - used < size {
                let evicted = oldest_eviction_candidate(&transaction, true)?
                    .or(oldest_eviction_candidate(&transaction, false)?)
                    .ok_or_else(|| {
                        ApiError::internal("storage accounting is inconsistent with live files")
                    })?;
                // Notices and file deletion commit together. In particular, a crash cannot
                // erase an unreceived file without leaving every recipient its advisory.
                if !evicted.downloaded {
                    enqueue_eviction_notices(&transaction, &evicted.id, &mut notified_recipients)?;
                }
                let directory = self.root.join(&evicted.id);
                transaction.execute(
                    "INSERT INTO pending_cleanup(file_id,dir,created_at) VALUES(?1,?2,?3)",
                    params![evicted.id, directory.to_string_lossy(), unix_time()?],
                )?;
                transaction.execute("DELETE FROM files WHERE file_id=?1", [&evicted.id])?;
                cleanup_debts.push(CleanupDebt {
                    file_id: evicted.id,
                    directory,
                });
                used -= evicted.size;
            }
            transaction.execute(
                "INSERT INTO files(file_id,upload_id,owner,size,chunks,received,status,created_at)
                 VALUES(?1,?2,?3,?4,?5,0,'uploading',?6)",
                params![
                    upload.file_id,
                    upload.upload_id,
                    owner,
                    size,
                    chunks,
                    unix_time()?
                ],
            )?;
            transaction.commit()?;
            (cleanup_debts, notified_recipients)
        };
        for recipient in notified_recipients {
            crate::api::mailbox::notifier(state, &recipient)
                .await
                .notify_waiters();
        }
        for debt in cleanup_debts {
            cleanup_debt(state, &debt.file_id, &debt.directory).await;
        }
        Ok(upload)
    }

    pub async fn put_chunk(
        &self,
        state: &AppState,
        owner: &str,
        upload_id: &str,
        index: u32,
        bytes: &[u8],
    ) -> Result<(), ApiError> {
        let upload = self.upload(state, owner, upload_id).await?;
        if index >= upload.chunks {
            return Err(ApiError::invalid("chunk index is out of range"));
        }
        let directory = self.root.join(&upload.file_id);
        fs::create_dir_all(&directory)
            .await
            .map_err(ApiError::internal)?;
        // Rename within the same directory makes readers see either complete version.
        let temporary = directory.join(format!("{}.{}.tmp", index, token()?));
        fs::write(&temporary, bytes)
            .await
            .map_err(ApiError::internal)?;
        fs::rename(&temporary, directory.join(format!("{index}.bin")))
            .await
            .map_err(ApiError::internal)?;

        let connection = state.db.0.lock().await;
        let transaction = connection.unchecked_transaction()?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO file_chunks(file_id,chunk_index) VALUES(?1,?2)",
            params![upload.file_id, index],
        )?;
        if inserted == 1 {
            transaction.execute(
                "UPDATE files SET received=received+1 WHERE file_id=?1",
                [&upload.file_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub async fn complete(
        &self,
        state: &AppState,
        owner: &str,
        upload_id: &str,
    ) -> Result<String, ApiError> {
        let upload = self.upload(state, owner, upload_id).await?;
        let connection = state.db.0.lock().await;
        let transaction = connection.unchecked_transaction()?;
        let received: u32 = transaction.query_row(
            "SELECT received FROM files WHERE file_id=?1",
            [&upload.file_id],
            |row| row.get(0),
        )?;
        if received != upload.chunks {
            return Err(ApiError::conflict("not all chunks have been uploaded"));
        }
        transaction.execute(
            "UPDATE files SET status='ready' WHERE file_id=?1",
            [&upload.file_id],
        )?;
        transaction.commit()?;
        Ok(upload.file_id)
    }

    pub async fn authorize_download(
        &self,
        state: &AppState,
        file_id: &str,
        device_id: &str,
    ) -> Result<(), ApiError> {
        let connection = state.db.0.lock().await;
        let owner = connection
            .query_row(
                "SELECT owner FROM files WHERE file_id=?1",
                [file_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        if owner == device_id {
            return Ok(());
        }
        let recipient = connection
            .query_row(
                "SELECT 1 FROM files_recipients WHERE file_id=?1 AND device_id=?2",
                params![file_id, device_id],
                |_| Ok(()),
            )
            .optional()?;
        if recipient.is_none() {
            return Err(ApiError::new(
                axum::http::StatusCode::FORBIDDEN,
                "forbidden",
                "file was not delivered to this device",
            ));
        }
        Ok(())
    }

    pub async fn acknowledge_download(
        &self,
        state: &AppState,
        file_id: &str,
        device_id: &str,
    ) -> Result<(), ApiError> {
        self.authorize_download(state, file_id, device_id).await?;
        if device_id
            == state.db.0.lock().await.query_row(
                "SELECT owner FROM files WHERE file_id=?1",
                [file_id],
                |row| row.get::<_, String>(0),
            )?
        {
            return Ok(());
        }
        state.db.0.lock().await.execute(
            "UPDATE file_refs SET downloaded_at=COALESCE(downloaded_at,?3)
             WHERE file_id=?1 AND recipient=?2",
            params![file_id, device_id, unix_time()?],
        )?;
        Ok(())
    }

    pub async fn metadata(&self, state: &AppState, file_id: &str) -> Result<Metadata, ApiError> {
        state
            .db
            .0
            .lock()
            .await
            .query_row(
                "SELECT size,chunks FROM files WHERE file_id=?1",
                [file_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?)),
            )
            .optional()?
            .map(|(size, chunks)| Metadata {
                size: size as u64,
                chunks,
            })
            .ok_or_else(ApiError::not_found)
    }

    pub async fn read_chunk(
        &self,
        state: &AppState,
        file_id: &str,
        index: u32,
    ) -> Result<Vec<u8>, ApiError> {
        let chunks: u32 = state
            .db
            .0
            .lock()
            .await
            .query_row(
                "SELECT chunks FROM files WHERE file_id=?1 AND status='ready'",
                [file_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        if index >= chunks {
            return Err(ApiError::not_found());
        }
        fs::read(self.root.join(file_id).join(format!("{index}.bin")))
            .await
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    ApiError::not_found()
                } else {
                    ApiError::internal(error)
                }
            })
    }

    async fn upload(
        &self,
        state: &AppState,
        owner: &str,
        upload_id: &str,
    ) -> Result<Upload, ApiError> {
        state
            .db
            .0
            .lock()
            .await
            .query_row(
                "SELECT file_id,chunks FROM files
                 WHERE upload_id=?1 AND owner=?2 AND status='uploading'",
                params![upload_id, owner],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?)),
            )
            .optional()?
            .map(|(file_id, chunks)| Upload {
                file_id,
                upload_id: upload_id.to_owned(),
                chunks,
            })
            .ok_or_else(ApiError::not_found)
    }
}
