use std::{
    env,
    error::Error as StdError,
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
    path::PathBuf,
};

pub const DEFAULT_MAX_STORAGE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

pub struct Config {
    pub bind: SocketAddr,
    /// Plaintext health-probe listener; deliberately separate from the authenticated API.
    /// Container orchestrators use TCP/HTTP probes, for which TLS termination is awkward.
    pub health_bind: SocketAddr,
    pub db_path: PathBuf,
    pub max_storage_bytes: u64,
    pub tls_paths: Option<(PathBuf, PathBuf)>,
}

impl Config {
    /// Environment-variable errors are startup-fatal; no request handlers run with invalid config.
    pub fn from_env() -> Result<Self, Box<dyn StdError>> {
        let bind = env::var("KITE_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8443".to_owned())
            .parse()?;
        let health_bind = env::var("KITE_HEALTH_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8444".to_owned())
            .parse()?;
        let db_path =
            PathBuf::from(env::var("KITE_DB_PATH").unwrap_or_else(|_| "./kite.db".into()));
        let max_storage_bytes = match env::var("KITE_MAX_STORAGE_BYTES") {
            Ok(value) => value.parse::<u64>().map_err(|error| {
                IoError::new(
                    ErrorKind::InvalidInput,
                    format!("KITE_MAX_STORAGE_BYTES must be an unsigned integer: {error}"),
                )
            })?,
            Err(_) => DEFAULT_MAX_STORAGE_BYTES,
        };
        let cert = env::var_os("KITE_TLS_CERT").map(PathBuf::from);
        let key = env::var_os("KITE_TLS_KEY").map(PathBuf::from);
        let tls_paths = match (cert, key) {
            (Some(cert), Some(key)) => Some((cert, key)),
            (None, None) => None,
            _ => {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    "KITE_TLS_CERT and KITE_TLS_KEY must be set together",
                )
                .into());
            }
        };
        Ok(Self {
            bind,
            health_bind,
            db_path,
            max_storage_bytes,
            tls_paths,
        })
    }
}
