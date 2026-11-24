use std::path::Path;

use rusqlite::Connection;
use tokio::sync::Mutex;

/// A single SQLite connection shared by handlers; WAL permits concurrent readers.
pub struct Db(pub Mutex<Connection>);

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
            CREATE TABLE IF NOT EXISTS opk_pool (
                owner_id TEXT NOT NULL,
                opk_id INTEGER NOT NULL,
                key BLOB NOT NULL,
                UNIQUE(owner_id, opk_id),
                FOREIGN KEY(owner_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );",
        )?;
        Ok(Self(Mutex::new(connection)))
    }
}
