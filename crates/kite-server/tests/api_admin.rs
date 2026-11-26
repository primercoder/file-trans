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
    base: String,
    client: reqwest::Client,
    _temp: TempDir,
}

fn client() -> reqwest::Client {
    kite_server::ensure_crypto_provider();
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

async fn spawn_server() -> Server {
    let temp = tempfile::tempdir().unwrap();
    let app = kite_server::router_with_db(&temp.path().join("kite.db"))
        .await
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let tls = kite_server::tls::self_signed().await.unwrap();
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls.config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    Server {
        base: format!("https://{addr}"),
        client: client(),
        _temp: temp,
    }
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

async fn stats(server: &Server, token: &str) -> Value {
    let response = server
        .client
        .get(format!("{}/stats", server.base))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

struct ChildServer {
    child: Child,
    client: reqwest::Client,
    base: String,
    health_base: String,
}

impl Drop for ChildServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[allow(clippy::zombie_processes)] // ChildServer::drop kills and waits on every normal return path.
async fn spawn_process(db: &std::path::Path, port: u16) -> ChildServer {
    let health_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(env!("CARGO_BIN_EXE_kite-server"))
        .env("KITE_BIND", format!("127.0.0.1:{port}"))
        .env("KITE_HEALTH_BIND", format!("127.0.0.1:{health_port}"))
        .env("KITE_DB_PATH", db)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let client = client();
    let base = format!("https://127.0.0.1:{port}");
    let health_base = format!("http://127.0.0.1:{health_port}");
    for _ in 0..100 {
        if client
            .get(format!("{health_base}/healthz"))
            .send()
            .await
            .is_ok()
        {
            return ChildServer {
                child,
                client,
                base,
                health_base,
            };
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server did not become ready");
}

#[tokio::test]
async fn custom_db_path_and_healthz_uptime() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("custom/kite.db");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let process = spawn_process(&db, port).await;
    assert!(db.is_file());

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let response = process
        .client
        .get(format!("{}/healthz", process.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let health: Value = response.json().await.unwrap();
    assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));
    assert!(health["uptime_s"].as_u64().unwrap() > 0);

    let response = process
        .client
        .get(format!("{}/healthz", process.health_base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let health: Value = response.json().await.unwrap();
    assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));
    assert!(health["uptime_s"].as_u64().unwrap() > 0);
    assert_eq!(
        process
            .client
            .get(format!("{}/api/v1/devices", process.health_base))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn stats_requires_auth_and_tracks_devices_and_pending_mail() {
    let server = spawn_server().await;
    assert_eq!(
        server
            .client
            .get(format!("{}/stats", server.base))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let a = register(&server, "Alice").await;
    let b = register(&server, "Bob").await;
    let initial = stats(&server, &a.token).await;
    assert_eq!(initial["devices"], 2);
    assert_eq!(initial["mailboxes_pending"], 0);
    assert_eq!(initial["storage_used"], 0);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let response = server
        .client
        .post(format!("{}/api/v1/send", server.base))
        .bearer_auth(&a.token)
        .json(&json!({
            "to": b.id,
            "kind": "message",
            "payload": B64.encode(b"pending"),
            "ts": ts,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(stats(&server, &b.token).await["mailboxes_pending"], 1);

    let response = server
        .client
        .post(format!("{}/api/v1/ack", server.base))
        .bearer_auth(&b.token)
        .json(&json!({"until_seq": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(stats(&server, &a.token).await["mailboxes_pending"], 0);
}

fn assert_startup_failure(variable: &str, value: &str, expected_error: &str) {
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kite-server"))
        .env("KITE_BIND", "127.0.0.1:0")
        .env("KITE_DB_PATH", temp.path().join("kite.db"))
        .env(variable, value)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(expected_error),
                "unexpected stderr: {stderr}"
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    child.kill().unwrap();
    panic!("invalid {variable} did not terminate startup");
}

#[test]
fn invalid_max_storage_bytes_fails_fast() {
    assert_startup_failure("KITE_MAX_STORAGE_BYTES", "abc", "KITE_MAX_STORAGE_BYTES");
}

#[test]
fn external_tls_requires_both_paths() {
    assert_startup_failure(
        "KITE_TLS_CERT",
        "certificate.pem",
        "KITE_TLS_CERT and KITE_TLS_KEY must be set together",
    );
    assert_startup_failure(
        "KITE_TLS_KEY",
        "key.pem",
        "KITE_TLS_CERT and KITE_TLS_KEY must be set together",
    );
}

#[tokio::test]
async fn external_tls_pem_is_loaded_and_fingerprinted() {
    let temp = tempfile::tempdir().unwrap();
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .unwrap();
    let cert = temp.path().join("certificate.pem");
    let key = temp.path().join("key.pem");
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    let tls = kite_server::tls::from_pem_files(&cert, &key).await.unwrap();
    assert_eq!(tls.cert_der, certified.cert.der().to_vec());
    assert_eq!(tls.fingerprint.len(), 64);
}
