use std::path::Path;

use rusqlite::{Connection, OptionalExtension as _, params};

use crate::{EngineError, InboxEvent, Result};

/// Local key material is protected only by filesystem permissions in M1.
/// This does **not** satisfy the design's platform secure-storage requirement;
/// keyring/DPAPI/Android Keystore integration is deferred to M3+.
pub struct Store {
    connection: Connection,
}

pub struct IdentityState {
    pub private_pem: String,
    pub token: Option<String>,
    pub spk_private: [u8; 32],
    pub name: Option<String>,
    pub opks: Vec<(u32, [u8; 32])>,
}

pub struct BackupIdentityState {
    pub private_pem: String,
    pub token: Option<String>,
    pub spk_private: [u8; 32],
    pub name: Option<String>,
    pub opks: Vec<(u32, [u8; 32])>,
}

pub struct BackupSession {
    pub peer: String,
    pub state: Vec<u8>,
    pub status: String,
}

pub struct PendingFile {
    pub peer: String,
    pub name: String,
    pub size: u64,
    pub fk: [u8; 32],
    pub header: Vec<u8>,
    pub content_hash: [u8; 32],
    pub downloaded: bool,
}

pub struct PendingUpload {
    pub upload_id: Option<String>,
    pub file_id: Option<String>,
    pub peer: String,
    pub name: String,
    pub size: u64,
    pub fk: [u8; 32],
    pub header: Vec<u8>,
    pub content_hash: [u8; 32],
}

pub type NewPendingFile = (String, String, String, u64, [u8; 32], Vec<u8>, [u8; 32]);

/// All local effects of one mailbox entry, committed with its disposition/cursor.
#[derive(Default)]
pub struct EntryOutcome {
    pub event: Option<InboxEvent>,
    pub pending_file: Option<NewPendingFile>,
    pub session: Option<(String, Vec<u8>, String)>,
    pub remove_session: Option<String>,
    pub pending: Option<(String, String, [u8; 32])>,
    pub remove_pending: Option<String>,
    pub consume_opk: Option<u32>,
    pub handshake_nonce: Option<(String, [u8; 32])>,
}

impl EntryOutcome {
    pub fn failed() -> Self {
        Self::default()
    }
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
            restrict_directory(parent)?;
        }
        let connection = Connection::open(path)?;
        restrict_file(path)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS identity(
                 id INTEGER PRIMARY KEY CHECK(id = 1), private_pem TEXT NOT NULL,
                 token TEXT, spk_private BLOB NOT NULL, name TEXT, opks BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sessions(
                 device_id TEXT PRIMARY KEY, state BLOB NOT NULL,
                 status TEXT NOT NULL CHECK(status IN ('pending_accept','pending_outgoing','paired'))
             );
             CREATE TABLE IF NOT EXISTS pending_pairing(
                 device_id TEXT PRIMARY KEY, name TEXT NOT NULL, challenge BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS meta(
                 key TEXT PRIMARY KEY, value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS inbox_dispositions(
                 seq INTEGER PRIMARY KEY,
                 outcome TEXT NOT NULL CHECK(outcome IN ('processed','failed'))
             );
             CREATE TABLE IF NOT EXISTS handshake_nonces(
                 device_id TEXT NOT NULL, ek_pub_hash BLOB NOT NULL,
                 PRIMARY KEY(device_id, ek_pub_hash)
             );
             CREATE TABLE IF NOT EXISTS pending_files(
                 file_id TEXT PRIMARY KEY, peer TEXT NOT NULL, name TEXT NOT NULL,
                 size INTEGER NOT NULL, fk BLOB NOT NULL, header BLOB NOT NULL,
                 content_hash BLOB NOT NULL, downloaded INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS pending_uploads(
                 content_hash BLOB PRIMARY KEY, upload_id TEXT UNIQUE, file_id TEXT UNIQUE,
                 peer TEXT NOT NULL, name TEXT NOT NULL, size INTEGER NOT NULL,
                 fk BLOB NOT NULL, header BLOB NOT NULL, created_at INTEGER NOT NULL
             );",
        )?;
        Ok(Self { connection })
    }

    pub fn identity(&self) -> Result<Option<IdentityState>> {
        identity(&self.connection)
    }

    pub fn backup(&self) -> Result<(IdentityState, Vec<BackupSession>)> {
        let state = identity(&self.connection)?
            .ok_or_else(|| EngineError::Protocol("identity is not initialized".into()))?;
        let mut statement = self
            .connection
            .prepare("SELECT device_id,state,status FROM sessions ORDER BY device_id")?;
        let sessions = statement
            .query_map([], |row| {
                Ok(BackupSession {
                    peer: row.get(0)?,
                    state: row.get(1)?,
                    status: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((state, sessions))
    }

    pub fn restore_backup(
        path: impl AsRef<Path>,
        state: &BackupIdentityState,
        sessions: &[BackupSession],
    ) -> Result<Self> {
        let store = Self::open(path)?;
        let transaction = store.connection.unchecked_transaction()?;
        save_identity(
            &transaction,
            &IdentityState {
                private_pem: state.private_pem.clone(),
                token: state.token.clone(),
                spk_private: state.spk_private,
                name: state.name.clone(),
                opks: state.opks.clone(),
            },
        )?;
        for session in sessions {
            save_session(&transaction, &session.peer, &session.state, &session.status)?;
        }
        transaction.commit()?;
        Ok(store)
    }

    pub fn save_identity(&self, state: &IdentityState) -> Result<()> {
        save_identity(&self.connection, state)
    }

    pub fn save_session(&self, peer: &str, state: &[u8], status: &str) -> Result<()> {
        save_session(&self.connection, peer, state, status)
    }

    pub fn session(&self, peer: &str) -> Result<Option<(Vec<u8>, String)>> {
        Ok(self
            .connection
            .query_row(
                "SELECT state,status FROM sessions WHERE device_id=?1",
                [peer],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn save_pending(&self, peer: &str, name: &str, challenge: [u8; 32]) -> Result<()> {
        self.connection.execute(
            "INSERT INTO pending_pairing(device_id,name,challenge) VALUES(?1,?2,?3)
             ON CONFLICT(device_id) DO UPDATE SET name=excluded.name,challenge=excluded.challenge",
            params![peer, name, challenge.as_slice()],
        )?;
        Ok(())
    }

    pub fn pending(&self, peer: &str) -> Result<Option<(String, [u8; 32])>> {
        self.connection
            .query_row(
                "SELECT name,challenge FROM pending_pairing WHERE device_id=?1",
                [peer],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(name, challenge)| {
                challenge
                    .try_into()
                    .map(|challenge| (name, challenge))
                    .map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            1,
                            "challenge".into(),
                            rusqlite::types::Type::Blob,
                        )
                    })
            })
            .transpose()
            .map_err(Into::into)
    }

    pub fn remove_pending(&self, peer: &str) -> Result<()> {
        self.connection
            .execute("DELETE FROM pending_pairing WHERE device_id=?1", [peer])?;
        Ok(())
    }

    pub fn rollback_pairing(&self, peer: &str, status: &str) -> Result<()> {
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "DELETE FROM sessions WHERE device_id=?1 AND status=?2",
            params![peer, status],
        )?;
        transaction.execute("DELETE FROM pending_pairing WHERE device_id=?1", [peer])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn cursor(&self) -> Result<i64> {
        Ok(self
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key='sync_cursor'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(0))
    }

    pub fn handshake_seen(&self, peer: &str, nonce: &[u8; 32]) -> Result<bool> {
        Ok(self
            .connection
            .query_row(
                "SELECT 1 FROM handshake_nonces WHERE device_id=?1 AND ek_pub_hash=?2",
                params![peer, nonce.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn pending_file(&self, file_id: &str) -> Result<Option<PendingFile>> {
        self.connection
            .query_row(
                "SELECT peer,name,size,fk,header,content_hash,downloaded
                 FROM pending_files WHERE file_id=?1",
                [file_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, bool>(6)?,
                    ))
                },
            )
            .optional()?
            .map(|(peer, name, size, fk, header, content_hash, downloaded)| {
                Ok::<PendingFile, rusqlite::Error>(PendingFile {
                    peer,
                    name,
                    size: u64::try_from(size).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?,
                    fk: fk.try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            3,
                            "fk".into(),
                            rusqlite::types::Type::Blob,
                        )
                    })?,
                    header,
                    content_hash: content_hash.try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            5,
                            "content_hash".into(),
                            rusqlite::types::Type::Blob,
                        )
                    })?,
                    downloaded,
                })
            })
            .transpose()
            .map_err(Into::into)
    }

    pub fn save_pending_upload(&self, upload: &PendingUpload, created_at: i64) -> Result<()> {
        let size = i64::try_from(upload.size)
            .map_err(|_| EngineError::Protocol("file size exceeds SQLite integer range".into()))?;
        self.connection.execute(
            "INSERT INTO pending_uploads(content_hash,upload_id,file_id,peer,name,size,fk,header,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![upload.content_hash.as_slice(), upload.upload_id, upload.file_id,
                upload.peer, upload.name, size, upload.fk.as_slice(), upload.header, created_at],
        )?;
        Ok(())
    }

    pub fn bind_pending_upload(
        &self,
        content_hash: &[u8; 32],
        upload_id: &str,
        file_id: &str,
    ) -> Result<()> {
        self.connection.execute(
            "UPDATE pending_uploads SET upload_id=?2,file_id=?3 WHERE content_hash=?1",
            params![content_hash.as_slice(), upload_id, file_id],
        )?;
        Ok(())
    }

    pub fn pending_upload(&self, content_hash: &[u8; 32]) -> Result<Option<PendingUpload>> {
        self.connection
            .query_row(
                "SELECT upload_id,file_id,peer,name,size,fk,header FROM pending_uploads
                 WHERE content_hash=?1",
                [content_hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()?
            .map(|(upload_id, file_id, peer, name, size, fk, header)| {
                Ok::<PendingUpload, rusqlite::Error>(PendingUpload {
                    upload_id,
                    file_id,
                    peer,
                    name,
                    size: u64::try_from(size).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?,
                    fk: fk.try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            5,
                            "fk".into(),
                            rusqlite::types::Type::Blob,
                        )
                    })?,
                    header,
                    content_hash: *content_hash,
                })
            })
            .transpose()
            .map_err(Into::into)
    }

    pub fn pending_upload_by_id(&self, upload_id: &str) -> Result<Option<PendingUpload>> {
        let content_hash: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT content_hash FROM pending_uploads WHERE upload_id=?1",
                [upload_id],
                |row| row.get(0),
            )
            .optional()?;
        self.pending_upload_for_hash(content_hash)
    }

    fn pending_upload_for_hash(
        &self,
        content_hash: Option<Vec<u8>>,
    ) -> Result<Option<PendingUpload>> {
        content_hash
            .map(|hash| {
                let hash: [u8; 32] = hash.try_into().map_err(|_| {
                    EngineError::Protocol("pending upload has invalid content hash".into())
                })?;
                self.pending_upload(&hash)?
                    .ok_or_else(|| EngineError::Protocol("pending upload disappeared".into()))
            })
            .transpose()
    }

    pub fn remove_pending_upload(&self, content_hash: &[u8; 32]) -> Result<()> {
        self.connection.execute(
            "DELETE FROM pending_uploads WHERE content_hash=?1",
            [content_hash.as_slice()],
        )?;
        Ok(())
    }

    pub fn mark_file_downloaded(&self, file_id: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE pending_files SET downloaded=1 WHERE file_id=?1",
            [file_id],
        )?;
        Ok(())
    }

    /// Atomically persists all entry effects, its durable disposition and cursor.
    /// ACK is deliberately outside this transaction: it is server-side cleanup.
    pub fn commit_entry(&mut self, seq: i64, outcome: EntryOutcome) -> Result<Option<InboxEvent>> {
        let transaction = self.connection.unchecked_transaction()?;
        if let Some((peer, state, status)) = &outcome.session {
            save_session(&transaction, peer, state, status)?;
        }
        if let Some(peer) = &outcome.remove_session {
            transaction.execute("DELETE FROM sessions WHERE device_id=?1", [peer])?;
        }
        if let Some((peer, name, challenge)) = &outcome.pending {
            transaction.execute(
                "INSERT INTO pending_pairing(device_id,name,challenge) VALUES(?1,?2,?3)
                 ON CONFLICT(device_id) DO UPDATE SET name=excluded.name,challenge=excluded.challenge",
                params![peer, name, challenge.as_slice()],
            )?;
        }
        if let Some(peer) = &outcome.remove_pending {
            transaction.execute("DELETE FROM pending_pairing WHERE device_id=?1", [peer])?;
        }
        if let Some((file_id, peer, name, size, fk, header, content_hash)) = &outcome.pending_file {
            let size = i64::try_from(*size).map_err(|_| {
                EngineError::Protocol("file size exceeds SQLite integer range".into())
            })?;
            transaction.execute(
                "INSERT INTO pending_files(file_id,peer,name,size,fk,header,content_hash,downloaded)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,0)
                 ON CONFLICT(file_id) DO UPDATE SET peer=excluded.peer,name=excluded.name,
                 size=excluded.size,fk=excluded.fk,header=excluded.header,
                 content_hash=excluded.content_hash,downloaded=0",
                params![file_id, peer, name, size, fk.as_slice(), header, content_hash.as_slice()],
            )?;
        }
        if let Some(id) = outcome.consume_opk {
            let mut state = identity(&transaction)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
            let index = state
                .opks
                .iter()
                .position(|(key_id, _)| *key_id == id)
                .ok_or_else(|| {
                    EngineError::Protocol("one-time prekey is no longer available".into())
                })?;
            state.opks.remove(index);
            save_identity(&transaction, &state)?;
        }
        if let Some((peer, nonce)) = &outcome.handshake_nonce {
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO handshake_nonces(device_id,ek_pub_hash) VALUES(?1,?2)",
                params![peer, nonce.as_slice()],
            )?;
            if inserted == 0 {
                return Err(EngineError::Protocol("replayed pair request".into()));
            }
        }
        let processed = outcome.event.is_some();
        transaction.execute(
            "INSERT INTO inbox_dispositions(seq,outcome) VALUES(?1,?2)",
            params![seq, if processed { "processed" } else { "failed" }],
        )?;
        set_cursor(&transaction, seq)?;
        transaction.commit()?;
        Ok(outcome.event)
    }
}

fn identity(connection: &Connection) -> Result<Option<IdentityState>> {
    connection
        .query_row(
            "SELECT private_pem,token,spk_private,name,opks FROM identity WHERE id=1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()?
        .map(|(private_pem, token, spk, name, opks)| {
            Ok::<IdentityState, rusqlite::Error>(IdentityState {
                private_pem,
                token,
                spk_private: spk.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        2,
                        "spk_private".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?,
                name,
                opks: bincode::deserialize(&opks).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Blob, error)
                })?,
            })
        })
        .transpose()
        .map_err(Into::into)
}

fn save_identity(connection: &Connection, state: &IdentityState) -> Result<()> {
    connection.execute(
        "INSERT INTO identity(id,private_pem,token,spk_private,name,opks) VALUES(1,?1,?2,?3,?4,?5)
         ON CONFLICT(id) DO UPDATE SET private_pem=excluded.private_pem,
         token=excluded.token,spk_private=excluded.spk_private,name=excluded.name,opks=excluded.opks",
        params![
            state.private_pem,
            state.token,
            state.spk_private.as_slice(),
            state.name,
            bincode::serialize(&state.opks)?
        ],
    )?;
    Ok(())
}

fn save_session(connection: &Connection, peer: &str, state: &[u8], status: &str) -> Result<()> {
    connection.execute(
        "INSERT INTO sessions(device_id,state,status) VALUES(?1,?2,?3)
         ON CONFLICT(device_id) DO UPDATE SET state=excluded.state,status=excluded.status",
        params![peer, state, status],
    )?;
    Ok(())
}

fn set_cursor(connection: &Connection, cursor: i64) -> Result<()> {
    connection.execute(
        "INSERT INTO meta(key,value) VALUES('sync_cursor',?1)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [cursor.to_string()],
    )?;
    Ok(())
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}
