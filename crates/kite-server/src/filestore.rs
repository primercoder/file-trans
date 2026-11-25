use std::path::PathBuf;

use rusqlite::{OptionalExtension as _, params};
use serde::Serialize;
use tokio::fs;

use crate::{
    api::{ApiError, token, unix_time},
    state::AppState,
};

#[derive(Clone)]
pub struct FileStore {
    root: PathBuf,
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

impl FileStore {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            root: data_dir.join("files"),
        }
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
        let size = i64::try_from(size).map_err(|_| ApiError::invalid("size is too large"))?;
        let upload = Upload {
            file_id: token()?,
            upload_id: token()?,
            chunks,
        };
        state.db.0.lock().await.execute(
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
