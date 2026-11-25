use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::{Mutex, Notify};

use crate::{db::Db, filestore::FileStore};

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub files: FileStore,
    pub online: Arc<Mutex<HashMap<String, Instant>>>,
    pub online_grace: Duration,
    pub pending_challenges: Arc<Mutex<HashMap<String, (String, Instant)>>>,
    pub notifications: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    pub started: Arc<Instant>,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        let files = FileStore::new(db.1.clone());
        Self {
            db: Arc::new(db),
            files,
            online: Arc::new(Mutex::new(HashMap::new())),
            online_grace: Duration::from_secs(90),
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
            notifications: Arc::new(Mutex::new(HashMap::new())),
            started: Arc::new(Instant::now()),
        }
    }
}
