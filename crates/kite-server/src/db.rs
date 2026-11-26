use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tokio::sync::Mutex;

/// A single SQLite connection shared by handlers; WAL permits concurrent readers.
pub struct Db(pub Mutex<Connection>, pub PathBuf);

impl Db {
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        // M1 schema creation. Later schema changes require explicit, versioned migrations.
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                ik_pub BLOB NOT NULL,
                spk BLOB NOT NULL,
                spk_sig BLOB NOT NULL,
                hw_hash TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                last_seen INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mailboxes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                from_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload BLOB NOT NULL,
                ts INTEGER NOT NULL,
                UNIQUE(owner_id, seq),
                FOREIGN KEY(owner_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS owner_seq (
                owner_id TEXT PRIMARY KEY,
                last_seq INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS opk_pool (
                owner_id TEXT NOT NULL,
                opk_id INTEGER NOT NULL,
                key BLOB NOT NULL,
                UNIQUE(owner_id, opk_id),
                FOREIGN KEY(owner_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                upload_id TEXT NOT NULL UNIQUE,
                owner TEXT NOT NULL,
                size INTEGER NOT NULL,
                chunks INTEGER NOT NULL,
                received INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL CHECK(status IN ('uploading', 'ready')),
                created_at INTEGER NOT NULL,
                FOREIGN KEY(owner) REFERENCES devices(device_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS file_chunks (
                file_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                PRIMARY KEY(file_id, chunk_index),
                FOREIGN KEY(file_id) REFERENCES files(file_id) ON DELETE CASCADE
            );
             -- Delivery authorization is derived only from the opaque file_hint,
             -- never from the encrypted filename or file key.
             CREATE TABLE IF NOT EXISTS files_recipients (
                 file_id TEXT NOT NULL,
                 device_id TEXT NOT NULL,
                 PRIMARY KEY(file_id, device_id),
                 FOREIGN KEY(file_id) REFERENCES files(file_id) ON DELETE CASCADE,
                 FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS file_refs (
                 file_id TEXT NOT NULL,
                 recipient TEXT NOT NULL,
                 downloaded_at INTEGER,
                 PRIMARY KEY(file_id, recipient),
                 FOREIGN KEY(file_id) REFERENCES files(file_id) ON DELETE CASCADE,
                 FOREIGN KEY(recipient) REFERENCES devices(device_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS pending_cleanup (
                 file_id TEXT PRIMARY KEY,
                 dir TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS groups (
                 group_id TEXT PRIMARY KEY,
                 name TEXT NOT NULL,
                 owner TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS group_members (
                 group_id TEXT NOT NULL,
                 device_id TEXT NOT NULL,
                 role TEXT NOT NULL,
                 PRIMARY KEY(group_id, device_id)
             );",
        )?;
        // M5: group fan-out keeps the group id as routing metadata (payload stays ciphertext).
        let group_column = connection
            .prepare("PRAGMA table_info(mailboxes)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .any(|column| column.is_ok_and(|name| name == "group_id"));
        if !group_column {
            connection.execute("ALTER TABLE mailboxes ADD COLUMN group_id TEXT", [])?;
        }
        // M2: track received ciphertext independently from the declared reservation.
        let actual_bytes_column = connection
            .prepare("PRAGMA table_info(files)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .any(|column| column.is_ok_and(|name| name == "actual_bytes"));
        if !actual_bytes_column {
            connection.execute(
                "ALTER TABLE files ADD COLUMN actual_bytes INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        let chunk_bytes_column = connection
            .prepare("PRAGMA table_info(file_chunks)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .any(|column| column.is_ok_and(|name| name == "actual_bytes"));
        if !chunk_bytes_column {
            connection.execute(
                "ALTER TABLE file_chunks ADD COLUMN actual_bytes INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        let data_dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        // Legacy chunks are files, not blobs. A one-time filesystem-length backfill
        // makes pre-fix in-flight uploads resumable; missing files stay zero so the
        // exact-size completion check still detects drift.
        if !chunk_bytes_column {
            backfill_actual_bytes(&connection, &data_dir)?;
        }
        Ok(Self(Mutex::new(connection), data_dir))
    }
}

fn backfill_actual_bytes(
    connection: &Connection,
    data_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let transaction = connection.unchecked_transaction()?;
    let chunks = {
        let mut statement = transaction.prepare(
            "SELECT file_id,chunk_index FROM file_chunks ORDER BY file_id,chunk_index",
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (file_id, index) in chunks {
        let path = data_dir
            .join("files")
            .join(&file_id)
            .join(format!("{index}.bin"));
        let actual = match std::fs::metadata(&path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        let actual = i64::try_from(actual)?;
        transaction.execute(
            "UPDATE file_chunks SET actual_bytes=?3 WHERE file_id=?1 AND chunk_index=?2",
            rusqlite::params![file_id, index, actual],
        )?;
    }
    transaction.execute(
        "UPDATE files SET actual_bytes=COALESCE(
             (SELECT SUM(actual_bytes) FROM file_chunks WHERE file_chunks.file_id=files.file_id),0
         )",
        [],
    )?;
    transaction.commit()?;
    Ok(())
}
