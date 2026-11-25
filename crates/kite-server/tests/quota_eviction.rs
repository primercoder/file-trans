use std::{
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey};
use kite_core::Identity;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tempfile::TempDir;

struct Device {
    id: String,
    token: String,
}

struct Server {
    child: Child,
    client: reqwest::Client,
    base: String,
    temp: TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[allow(clippy::zombie_processes)] // Server::drop kills and waits on every normal return path.
async fn spawn_server(quota: u64) -> Server {
    let temp = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(env!("CARGO_BIN_EXE_kite-server"))
        .env("KITE_BIND", format!("127.0.0.1:{port}"))
        .env("KITE_DB_PATH", temp.path().join("kite.db"))
        .env("KITE_HEALTH_BIND", "127.0.0.1:0")
        .env("KITE_MAX_STORAGE_BYTES", quota.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let base = format!("https://127.0.0.1:{port}");
    for _ in 0..100 {
        if client.get(format!("{base}/healthz")).send().await.is_ok() {
            return Server {
                child,
                client,
                base,
                temp,
            };
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server did not become ready");
}

async fn register(server: &Server, name: &str) -> Device {
    let identity = Identity::generate();
    let id = identity.device_id();
    let (_private, spk, spk_sig) = kite_core::generate_spk(&identity);
    let signing_key = SigningKey::from_bytes(&{
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_pem(&identity.private_pem())
            .unwrap()
            .to_bytes()
    });
    let signature = signing_key.sign(format!("register||{id}||{name}").as_bytes());
    let response: Value = server
        .client
        .post(format!("{}/api/v1/register", server.base))
        .json(&json!({
            "device_id": id,
            "ik_pub": B64.encode(identity.ed25519_public_key()),
            "name": name,
            "hw_hash": "test-hardware",
            "spk": B64.encode(spk),
            "spk_sig": B64.encode(spk_sig),
            "opks": [],
            "sig": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(response["token"].is_string(), "{response}");
    Device {
        id,
        token: response["token"].as_str().unwrap().to_owned(),
    }
}

async fn init(server: &Server, token: &str, size: usize) -> (StatusCode, Value) {
    let response = server
        .client
        .post(format!("{}/api/v1/files/init", server.base))
        .bearer_auth(token)
        .json(&json!({"size": size, "chunks": 1}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap())
}

async fn upload(server: &Server, owner: &Device, bytes: &[u8]) -> String {
    let (status, upload) = init(server, &owner.token, bytes.len()).await;
    assert_eq!(status, StatusCode::OK, "{upload}");
    let upload_id = upload["upload_id"].as_str().unwrap();
    let response = server
        .client
        .put(format!("{}/api/v1/files/{upload_id}/chunk/0", server.base))
        .bearer_auth(&owner.token)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = server
        .client
        .post(format!("{}/api/v1/files/{upload_id}/complete", server.base))
        .bearer_auth(&owner.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    upload["file_id"].as_str().unwrap().to_owned()
}

async fn deliver(server: &Server, owner: &Device, recipient: &Device, file_id: &str) {
    let response = server
        .client
        .post(format!("{}/api/v1/send", server.base))
        .bearer_auth(&owner.token)
        .json(&json!({
            "to": recipient.id,
            "kind": "file",
            "payload": B64.encode(b"encrypted file envelope"),
            "ts": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "file_hint": B64.encode(file_id),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn acknowledge(server: &Server, recipient: &Device, file_id: &str) {
    let response = server
        .client
        .post(format!(
            "{}/api/v1/files/{file_id}/ack-download",
            server.base
        ))
        .bearer_auth(&recipient.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn metadata_status(server: &Server, owner: &Device, file_id: &str) -> StatusCode {
    server
        .client
        .get(format!("{}/api/v1/files/{file_id}/meta", server.base))
        .bearer_auth(&owner.token)
        .send()
        .await
        .unwrap()
        .status()
}

async fn storage_used(server: &Server, device: &Device) -> u64 {
    server
        .client
        .get(format!("{}/stats", server.base))
        .bearer_auth(&device.token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["storage_used"]
        .as_u64()
        .unwrap()
}

async fn eviction_notices(server: &Server, recipient: &Device) -> Vec<String> {
    let response = server
        .client
        .get(format!("{}/api/v1/sync?since=0", server.base))
        .bearer_auth(&recipient.token)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str::<Vec<Value>>(&body)
        .unwrap()
        .iter()
        .filter(|entry| entry["kind"] == "file_evicted")
        .map(|entry| {
            let body = B64.decode(entry["payload"].as_str().unwrap()).unwrap();
            serde_json::from_slice::<Value>(&body).unwrap()["file_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

fn set_created_at(server: &Server, file_id: &str, created_at: i64) {
    rusqlite::Connection::open(server.temp.path().join("kite.db"))
        .unwrap()
        .execute(
            "UPDATE files SET created_at=?1 WHERE file_id=?2",
            rusqlite::params![created_at, file_id],
        )
        .unwrap();
}

#[tokio::test]
async fn received_files_are_evicted_before_younger_unreceived_files_and_stats_are_real() {
    let server = spawn_server(23).await;
    let owner = register(&server, "Owner").await;
    let recipient = register(&server, "Recipient").await;
    let a = upload(&server, &owner, b"12345678").await;
    deliver(&server, &owner, &recipient, &a).await;
    acknowledge(&server, &recipient, &a).await;
    set_created_at(&server, &a, 100);
    let b = upload(&server, &owner, b"abcdefgh").await;
    deliver(&server, &owner, &recipient, &b).await;
    set_created_at(&server, &b, 200);
    assert_eq!(storage_used(&server, &owner).await, 16);

    let c = upload(&server, &owner, b"ABCDEFGH").await;
    assert_eq!(
        metadata_status(&server, &owner, &a).await,
        StatusCode::NOT_FOUND
    );
    assert!(!server.temp.path().join("files").join(&a).exists());
    assert_eq!(metadata_status(&server, &owner, &b).await, StatusCode::OK);
    assert_eq!(metadata_status(&server, &owner, &c).await, StatusCode::OK);
    assert_eq!(storage_used(&server, &owner).await, 16);
    assert!(eviction_notices(&server, &recipient).await.is_empty());
}

#[tokio::test]
async fn unreceived_eviction_notifies_every_recipient_before_deleting_chunks() {
    let server = spawn_server(16).await;
    let owner = register(&server, "Owner").await;
    let first = register(&server, "First").await;
    let second = register(&server, "Second").await;
    let a = upload(&server, &owner, b"recv").await;
    deliver(&server, &owner, &first, &a).await;
    acknowledge(&server, &first, &a).await;
    set_created_at(&server, &a, 100);
    let b = upload(&server, &owner, b"pending!").await;
    deliver(&server, &owner, &first, &b).await;
    deliver(&server, &owner, &second, &b).await;
    set_created_at(&server, &b, 200);
    assert_eq!(storage_used(&server, &owner).await, 12);

    let c = upload(&server, &owner, b"new-file-12").await;
    assert_eq!(
        metadata_status(&server, &owner, &a).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        metadata_status(&server, &owner, &b).await,
        StatusCode::NOT_FOUND
    );
    assert!(!server.temp.path().join("files").join(&b).exists());
    assert_eq!(metadata_status(&server, &owner, &c).await, StatusCode::OK);
    assert_eq!(storage_used(&server, &owner).await, 11);
    assert_eq!(eviction_notices(&server, &first).await, vec![b.clone()]);
    assert_eq!(eviction_notices(&server, &second).await, vec![b]);
    let owner_entries = server
        .client
        .get(format!("{}/api/v1/sync?since=0", server.base))
        .bearer_auth(&owner.token)
        .send()
        .await
        .unwrap()
        .json::<Vec<Value>>()
        .await
        .unwrap();
    assert!(
        owner_entries
            .iter()
            .all(|entry| entry["kind"] != "file_evicted")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn cleanup_failure_preserves_committed_init_and_startup_reconciles_debt() {
    use std::os::unix::fs::PermissionsExt as _;

    let server = spawn_server(8).await;
    let owner = register(&server, "Owner").await;
    let recipient = register(&server, "Recipient").await;
    let existing = upload(&server, &owner, b"12345678").await;
    deliver(&server, &owner, &recipient, &existing).await;
    acknowledge(&server, &recipient, &existing).await;
    let files = server.temp.path().join("files");
    let evicted = files.join(&existing);
    std::fs::set_permissions(&files, std::fs::Permissions::from_mode(0o500)).unwrap();

    let (status, upload) = init(&server, &owner.token, 8).await;
    assert_eq!(status, StatusCode::OK, "{upload}");
    assert!(upload["upload_id"].is_string());
    assert_eq!(
        metadata_status(&server, &owner, &existing).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(storage_used(&server, &owner).await, 8);
    let debt: i64 = rusqlite::Connection::open(server.temp.path().join("kite.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM pending_cleanup", [], |row| row.get(0))
        .unwrap();
    assert_eq!(debt, 1);
    assert!(evicted.exists());

    std::fs::set_permissions(&files, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = kite_server::state::AppState::new(
        kite_server::db::Db::open(&server.temp.path().join("kite.db")).unwrap(),
    );
    kite_server::filestore::reconcile_pending_cleanup(&state).await;
    assert!(!evicted.exists());
    let debt: i64 = rusqlite::Connection::open(server.temp.path().join("kite.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM pending_cleanup", [], |row| row.get(0))
        .unwrap();
    assert_eq!(debt, 0);
}

#[tokio::test]
async fn reconciliation_removes_real_directories_and_drops_missing_paths() {
    let temp = tempfile::tempdir().unwrap();
    let state = kite_server::state::AppState::new(
        kite_server::db::Db::open(&temp.path().join("kite.db")).unwrap(),
    );
    let directory = temp.path().join("orphan");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("0.bin"), b"orphan").unwrap();
    let missing = temp.path().join("already-gone");
    let connection = rusqlite::Connection::open(temp.path().join("kite.db")).unwrap();
    for (file_id, path) in [("orphan", &directory), ("missing", &missing)] {
        connection
            .execute(
                "INSERT INTO pending_cleanup(file_id,dir,created_at) VALUES(?1,?2,1)",
                rusqlite::params![file_id, path.to_string_lossy()],
            )
            .unwrap();
    }
    drop(connection);

    kite_server::filestore::reconcile_pending_cleanup(&state).await;
    assert!(!directory.exists());
    let remaining: i64 = state
        .db
        .0
        .lock()
        .await
        .query_row("SELECT COUNT(*) FROM pending_cleanup", [], |row| row.get(0))
        .unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn oversized_file_is_rejected_without_storing_or_evicting() {
    let server = spawn_server(16).await;
    let owner = register(&server, "Owner").await;
    let recipient = register(&server, "Recipient").await;
    let existing = upload(&server, &owner, b"12345678").await;
    deliver(&server, &owner, &recipient, &existing).await;
    acknowledge(&server, &recipient, &existing).await;

    let (status, body) = init(&server, &owner.token, 17).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(
        metadata_status(&server, &owner, &existing).await,
        StatusCode::OK
    );
    assert_eq!(storage_used(&server, &owner).await, 8);
    assert!(eviction_notices(&server, &recipient).await.is_empty());
    let files = server.temp.path().join("files");
    assert_eq!(std::fs::read_dir(files).unwrap().count(), 1);
}
