use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// One server account. Each account owns its own identity, contacts, messages
/// and downloaded files, so several servers can be used side by side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub server_url: String,
    /// Optional certificate pin (self-signed deployments). Empty means the
    /// platform trust store / public WebPKI roots are used.
    #[serde(default)]
    pub fingerprint: Option<String>,
    pub device_id: Option<String>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub accounts: Vec<Account>,
    pub active: Option<String>,
    /// "system" | "light" | "dark"
    pub theme: String,
    /// "zh" | "en"
    pub locale: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            accounts: Vec::new(),
            active: None,
            theme: "system".into(),
            locale: "zh".into(),
        }
    }
}

impl Settings {
    pub fn load(dir: &Path) -> Self {
        let Ok(bytes) = std::fs::read(dir.join("settings.json")) else {
            return Self::default();
        };
        // Only files that actually carry the multi-account shape are parsed as
        // Settings; the old single-account file would otherwise silently become
        // an empty account list because unknown fields are ignored.
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if value.get("accounts").is_some() {
                if let Ok(settings) = serde_json::from_value::<Settings>(value) {
                    return settings;
                }
            }
        }
        // Migrate the single-account format used before multi-server support.
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(url) = value["server_url"].as_str().filter(|url| !url.is_empty()) {
                let fingerprint = value["fingerprint"]
                    .as_str()
                    .filter(|pin| !pin.is_empty())
                    .map(str::to_owned);
                let name = value["device_name"].as_str().map(str::to_owned);
                let account = Account {
                    id: account_id(url),
                    server_url: url.trim_end_matches('/').to_owned(),
                    fingerprint,
                    device_id: None,
                    name,
                };
                return Self {
                    active: Some(account.id.clone()),
                    accounts: vec![account],
                    ..Self::default()
                };
            }
        }
        Self::default()
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("settings.json"), json).map_err(|e| e.to_string())
    }

    pub fn active_account(&self) -> Option<&Account> {
        self.active
            .as_ref()
            .and_then(|id| self.accounts.iter().find(|account| &account.id == id))
    }

    pub fn account(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|account| account.id == id)
    }

    pub fn upsert_account(&mut self, account: Account) {
        match self
            .accounts
            .iter_mut()
            .find(|existing| existing.id == account.id)
        {
            Some(existing) => *existing = account,
            None => self.accounts.push(account),
        }
    }

    pub fn remove_account(&mut self, id: &str) {
        self.accounts.retain(|account| account.id != id);
        if self.active.as_deref() == Some(id) {
            self.active = self.accounts.first().map(|account| account.id.clone());
        }
    }
}

/// Stable per-server id: also the on-disk profile directory name.
pub fn account_id(server_url: &str) -> String {
    let digest = Sha256::digest(server_url.trim_end_matches('/').as_bytes());
    hex::encode(&digest[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("kite-settings-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn settings_roundtrip_keeps_multiple_accounts() {
        let dir = dir("roundtrip");
        let mut settings = Settings::default();
        settings.accounts.push(Account {
            id: account_id("https://a.test"),
            server_url: "https://a.test".into(),
            fingerprint: None,
            device_id: Some("aa".repeat(16)),
            name: Some("Alice".into()),
        });
        settings.accounts.push(Account {
            id: account_id("https://b.test"),
            server_url: "https://b.test".into(),
            fingerprint: Some("ab".repeat(32)),
            device_id: None,
            name: None,
        });
        settings.active = Some(account_id("https://b.test"));
        settings.save(&dir).unwrap();
        let loaded = Settings::load(&dir);
        assert_eq!(loaded, settings);
        assert_eq!(loaded.active_account().unwrap().server_url, "https://b.test");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_single_account_settings_are_migrated() {
        let dir = dir("legacy");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("settings.json"),
            br#"{"server_url":"https://legacy.test:8443","fingerprint":"cdcd","device_name":"desk"}"#,
        )
        .unwrap();
        let loaded = Settings::load(&dir);
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.accounts[0].server_url, "https://legacy.test:8443");
        assert_eq!(loaded.accounts[0].fingerprint.as_deref(), Some("cdcd"));
        assert_eq!(loaded.active.as_deref(), Some(loaded.accounts[0].id.as_str()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_the_active_account_selects_another() {
        let mut settings = Settings::default();
        for url in ["https://a.test", "https://b.test"] {
            settings.accounts.push(Account {
                id: account_id(url),
                server_url: url.into(),
                fingerprint: None,
                device_id: None,
                name: None,
            });
        }
        settings.active = Some(account_id("https://a.test"));
        settings.remove_account(&account_id("https://a.test"));
        assert_eq!(settings.active.as_deref(), Some(account_id("https://b.test").as_str()));
        settings.remove_account(&account_id("https://b.test"));
        assert!(settings.active.is_none());
    }
}
