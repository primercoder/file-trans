use std::{collections::HashMap, sync::Arc, time::Instant};

use tokio::sync::Mutex;

use crate::db::Db;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub online: Arc<Mutex<HashMap<String, ()>>>,
    pub pending_challenges: Arc<Mutex<HashMap<String, (String, Instant)>>>,
    pub started: Arc<Instant>,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        Self {
            db: Arc::new(db),
            online: Arc::new(Mutex::new(HashMap::new())),
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
            started: Arc::new(Instant::now()),
        }
    }
}
