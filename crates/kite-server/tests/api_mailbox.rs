use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn send(
    server: &Server,
    sender: &Device,
    to: &str,
    kind: &str,
    payload: &[u8],
    ts: i64,
) -> (StatusCode, Value) {
    let response = server
        .client
        .post(format!("{}/api/v1/send", server.base))
        .bearer_auth(&sender.token)
        .json(&json!({"to": to, "kind": kind, "payload": B64.encode(payload), "ts": ts}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.json().await.unwrap();
    (status, body)
}

async fn sync(server: &Server, device: &Device, since: i64) -> Vec<Value> {
    server
        .client
        .get(format!("{}/api/v1/sync?since={since}", server.base))
        .bearer_auth(&device.token)
        .send()
        .await
        .unwrap()
        .json::<Vec<Value>>()
        .await
        .unwrap()
}

#[tokio::test]
async fn send_cursor_ack_offline_and_validation() {
    let server = spawn_server().await;
    let a = register(&server, "Alice").await;
    let b = register(&server, "Bob").await;
    let c = register(&server, "Carol").await;

    let (status, body) = send(&server, &a, &b.id, "message", b"one", now()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["seq"], 1);
    let entries = sync(&server, &b, 0).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["seq"], 1);
    assert_eq!(entries[0]["from"], a.id);
    assert_eq!(entries[0]["kind"], "message");
    assert_eq!(
        B64.decode(entries[0]["payload"].as_str().unwrap()).unwrap(),
        b"one"
    );
    assert!(entries[0]["ts"].is_i64());

    let (_, body) = send(&server, &a, &b.id, "message", b"two", now()).await;
    assert_eq!(body["seq"], 2);
    let entries = sync(&server, &b, 1).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["seq"], 2);

    let deleted: Value = server
        .client
        .post(format!("{}/api/v1/ack", server.base))
        .bearer_auth(&b.token)
        .json(&json!({"until_seq": 2}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(deleted["deleted"], 2);
    assert!(sync(&server, &b, 0).await.is_empty());

    let (_, body) = send(&server, &a, &b.id, "message", b"three", now()).await;
    assert_eq!(body["seq"], 3, "ACK must not reset the cursor sequence");
    let entries = sync(&server, &b, 2).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["seq"], 3);

    send(&server, &a, &c.id, "message", b"offline", now()).await;
    let entries = sync(&server, &c, 0).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["seq"], 1);

    let nonexistent = "0123456789abcdef0123456789abcdef";
    let (status, _) = send(&server, &a, nonexistent, "message", b"bad", now()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let connection = rusqlite::Connection::open(server._temp.path().join("kite.db")).unwrap();
    let rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM mailboxes WHERE owner_id = ?1",
            [nonexistent],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "404 must not enqueue");
    let (status, _) = send(&server, &a, &c.id, "message", b"future", now() + 300).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = send(&server, &a, &c.id, "message", b"past", now() - 300).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = send(
        &server,
        &a,
        &c.id,
        "message",
        &vec![0; 256 * 1024 + 1],
        now(),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(sync(&server, &c, 0).await.len(), 1);
}

#[tokio::test]
async fn long_poll_wakes_on_send_and_pairing_relays() {
    let server = spawn_server().await;
    let a = register(&server, "Alice").await;
    let b = register(&server, "Bob").await;
    let waiting_server = &server;
    let waiting_b = &b;
    let poll = async move {
        let started = Instant::now();
        let response = waiting_server
            .client
            .get(format!(
                "{}/api/v1/sync?since=0&wait=1",
                waiting_server.base
            ))
            .bearer_auth(&waiting_b.token)
            .send()
            .await
            .unwrap();
        (
            started.elapsed(),
            response.json::<Vec<Value>>().await.unwrap(),
        )
    };
    let send = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let response = a_pair_request(&server, &a, &b.id).await;
        assert_eq!(response["seq"], 1);
    };
    let ((elapsed, entries), ()) = tokio::join!(poll, send);
    assert!(
        elapsed < Duration::from_millis(1500),
        "long poll took {elapsed:?}"
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["kind"], "pair_req");

    let response = server
        .client
        .post(format!("{}/api/v1/pair/respond", server.base))
        .bearer_auth(&b.token)
        .json(&json!({"to": a.id, "accept": true, "payload": B64.encode(b"accepted")}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let entries = sync(&server, &a, 0).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["kind"], "pair_resp");
    assert_eq!(entries[0]["from"], b.id);

    let response = server
        .client
        .post(format!("{}/api/v1/pair/request", server.base))
        .bearer_auth(&a.token)
        .json(&json!({"to": "0123456789abcdef0123456789abcdef", "payload": ""}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

async fn a_pair_request(server: &Server, a: &Device, to: &str) -> Value {
    server
        .client
        .post(format!("{}/api/v1/pair/request", server.base))
        .bearer_auth(&a.token)
        .json(&json!({"to": to, "payload": B64.encode(b"pair")}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

struct ChildServer {
    child: Child,
    client: reqwest::Client,
    base: String,
}

impl Drop for ChildServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn spawn_process(db: &std::path::Path, port: u16) -> ChildServer {
    let child = Command::new(env!("CARGO_BIN_EXE_kite-server"))
        .env("KITE_BIND", format!("127.0.0.1:{port}"))
        .env("KITE_DB_PATH", db)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let client = client();
    let base = format!("https://127.0.0.1:{port}");
    for _ in 0..100 {
        if client.get(format!("{base}/healthz")).send().await.is_ok() {
            return ChildServer {
                child,
                client,
                base,
            };
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server did not become ready");
}

#[tokio::test]
async fn unacked_mail_survives_sigkill_and_restart() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("kite.db");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut process = spawn_process(&db, port).await;
    let inline = Server {
        base: process.base.clone(),
        client: process.client.clone(),
        _temp: tempfile::tempdir().unwrap(),
    };
    let a = register(&inline, "Alice").await;
    let b = register(&inline, "Bob").await;
    send(&inline, &a, &b.id, "message", b"one", now()).await;
    send(&inline, &a, &b.id, "message", b"two", now()).await;

    process.child.kill().unwrap();
    process.child.wait().unwrap();
    drop(process);
    let restarted = spawn_process(&db, port).await;
    let response = restarted
        .client
        .get(format!("{}/api/v1/sync?since=0", restarted.base))
        .bearer_auth(&b.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let entries = response.json::<Vec<Value>>().await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["seq"], 1);
    assert_eq!(entries[1]["seq"], 2);
}
