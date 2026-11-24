use std::path::Path;

use rusqlite::{Connection, OptionalExtension as _, params};

use crate::Result;

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

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS identity(
                 id INTEGER PRIMARY KEY CHECK(id = 1), private_pem TEXT NOT NULL,
                 token TEXT, spk_private BLOB NOT NULL, name TEXT, opks BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sessions(
                 device_id TEXT PRIMARY KEY, state BLOB NOT NULL,
                 status TEXT NOT NULL CHECK(status IN ('pending_accept','paired'))
             );
             CREATE TABLE IF NOT EXISTS pending_pairing(
                 device_id TEXT PRIMARY KEY, name TEXT NOT NULL, challenge BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS meta(
                 key TEXT PRIMARY KEY, value TEXT NOT NULL
             );",
        )?;
        Ok(Self { connection })
    }

    pub fn identity(&self) -> Result<Option<IdentityState>> {
        self.connection
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
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Blob,
                            error,
                        )
                    })?,
                })
            })
            .transpose()
            .map_err(Into::into)
    }

    pub fn save_identity(&self, state: &IdentityState) -> Result<()> {
        self.connection.execute(
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

    pub fn save_session(&self, peer: &str, state: &[u8], status: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO sessions(device_id,state,status) VALUES(?1,?2,?3)
             ON CONFLICT(device_id) DO UPDATE SET state=excluded.state,status=excluded.status",
            params![peer, state, status],
        )?;
        Ok(())
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

    pub fn take_opk(&mut self, id: u32) -> Result<Option<[u8; 32]>> {
        let mut state = self
            .identity()?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let index = state.opks.iter().position(|(key_id, _)| *key_id == id);
        let Some(index) = index else {
            return Ok(None);
        };
        let key = state.opks.remove(index).1;
        self.save_identity(&state)?;
        Ok(Some(key))
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

    pub fn set_cursor(&self, cursor: i64) -> Result<()> {
        self.connection.execute(
            "INSERT INTO meta(key,value) VALUES('sync_cursor',?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [cursor.to_string()],
        )?;
        Ok(())
    }
}
