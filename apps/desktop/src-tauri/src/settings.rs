use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Settings {
    pub server_url: Option<String>,
    pub fingerprint: Option<String>,
    pub device_name: Option<String>,
}

impl Settings {
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join("settings.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("settings.json"), json).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_roundtrip() {
        let dir = std::env::temp_dir().join(format!("kite-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let settings = Settings {
            server_url: Some("https://example.test:8443".into()),
            fingerprint: Some("ab".repeat(32)),
            device_name: Some("desk".into()),
        };
        settings.save(&dir).unwrap();
        let loaded = Settings::load(&dir);
        assert_eq!(loaded.server_url, settings.server_url);
        assert_eq!(loaded.fingerprint, settings.fingerprint);
        assert_eq!(loaded.device_name, settings.device_name);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
