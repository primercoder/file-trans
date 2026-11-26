use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatRecord {
    pub peer: String,
    /// "out" for local sends, "in" for received events, "system" for notices.
    pub direction: String,
    /// "text" | "file" | "file_available" | "system"
    pub kind: String,
    pub text: String,
    #[serde(default)]
    pub file_id: Option<String>,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    pub ts: i64,
}

pub struct ChatLog {
    path: PathBuf,
}

impl ChatLog {
    pub fn new(dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(dir);
        Self { path: dir.join("chat.jsonl") }
    }

    pub fn append(&self, record: &ChatRecord) -> Result<(), String> {
        let mut line = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        line.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        file.write_all(&line).map_err(|e| e.to_string())
    }

    pub fn history(&self, peer: &str, limit: usize) -> Result<Vec<ChatRecord>, String> {
        let Ok(bytes) = std::fs::read(&self.path) else {
            return Ok(Vec::new());
        };
        let mut records: Vec<ChatRecord> = Vec::new();
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            if let Ok(record) = serde_json::from_slice::<ChatRecord>(line) {
                if record.peer == peer {
                    records.push(record);
                }
            }
        }
        if records.len() > limit {
            records.drain(0..records.len() - limit);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(peer: &str, kind: &str, text: &str, ts: i64) -> ChatRecord {
        ChatRecord {
            peer: peer.into(),
            direction: "in".into(),
            kind: kind.into(),
            text: text.into(),
            file_id: None,
            file_name: None,
            size: None,
            ts,
        }
    }

    #[test]
    fn append_and_filter_history() {
        let dir = std::env::temp_dir().join(format!("kite-chat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = ChatLog::new(&dir);
        log.append(&record("alice", "text", "one", 1)).unwrap();
        log.append(&record("bob", "text", "other", 2)).unwrap();
        log.append(&record("alice", "text", "two", 3)).unwrap();
        let history = log.history("alice", 10).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].text, "one");
        assert_eq!(history[1].text, "two");
        let limited = log.history("alice", 1).unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].text, "two");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
