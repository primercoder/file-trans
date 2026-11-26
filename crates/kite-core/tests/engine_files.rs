use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey as _};
use kite_core::{Engine, EngineError, Identity, InboxEvent, generate_spk};
use rand::{RngCore as _, rng};
use reqwest::StatusCode;
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;

struct TestServer {
    base_url: String,
    fingerprint: String,
    child: Child,
    temp: TempDir,
}

impl TestServer {
    fn spawn() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let db_path = temp.path().join("server.db");
        let server_binary = std::env::var("CARGO_BIN_EXE_kite-server")
            .expect("run with the workspace test harness providing kite-server's binary path");
        let child = Command::new(server_binary)
            .env("KITE_BIND", address.to_string())
            .env("KITE_DB_PATH", &db_path)
            .env("KITE_HEALTH_BIND", "127.0.0.1:0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let fingerprint_path = temp.path().join("fingerprint.txt");
        let deadline = Instant::now() + Duration::from_secs(10);
        let fingerprint = loop {
            if let Ok(value) = fs::read_to_string(&fingerprint_path)
                && !value.trim().is_empty()
            {
                break value.trim().to_owned();
            }
            assert!(Instant::now() < deadline, "server did not start");
            std::thread::sleep(Duration::from_millis(25));
        };
        Self {
            base_url: format!("https://{address}"),
            fingerprint,
            child,
            temp,
        }
    }

    fn db(&self) -> Connection {
        let connection = Connection::open(self.temp.path().join("server.db")).unwrap();
        connection.busy_timeout(Duration::from_secs(2)).unwrap();
        connection
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn engine(temp: &TempDir, name: &str, server: &TestServer) -> Engine {
    let path: PathBuf = temp.path().join(format!("{name}.db"));
    Engine::open(path, &server.base_url, &server.fingerprint).unwrap()
}

async fn paired_clients(temp: &TempDir, server: &TestServer) -> (Engine, Engine, String, String) {
    let mut alice = engine(temp, "alice", server);
    let mut bob = engine(temp, "bob", server);
    alice.register("Alice", "alice-hardware").await.unwrap();
    bob.register("Bob", "bob-hardware").await.unwrap();
    let alice_id = alice.device_id().to_owned();
    let bob_id = bob.device_id().to_owned();
    alice.start_pairing(&bob_id).await.unwrap();
    assert!(matches!(
        bob.poll_once().await.unwrap().as_slice(),
        [InboxEvent::PairRequest { .. }]
    ));
    bob.confirm_pairing(&alice_id).await.unwrap();
    assert!(matches!(
        alice.poll_once().await.unwrap().as_slice(),
        [InboxEvent::PairResponse { accepted: true, .. }]
    ));
    (alice, bob, alice_id, bob_id)
}

async fn register_raw(server: &TestServer) -> String {
    let identity = Identity::generate();
    let id = identity.device_id();
    let (_private, spk, spk_sig) = generate_spk(&identity);
    let signing_key = SigningKey::from_pkcs8_pem(&identity.private_pem()).unwrap();
    let signature = signing_key.sign(format!("register||{id}||Carol").as_bytes());
    let response = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(format!("{}/api/v1/register", server.base_url))
        .json(&json!({
            "device_id": id,
            "ik_pub": B64.encode(identity.ed25519_public_key()),
            "name": "Carol",
            "hw_hash": "carol-hardware",
            "spk": B64.encode(spk),
            "spk_sig": B64.encode(spk_sig),
            "opks": [],
            "sig": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    body["token"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn file_round_trip_recipient_authorization_ack_and_idempotent_download() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let (mut alice, mut bob, _alice_id, bob_id) = paired_clients(&temp, &server).await;
    let mut original = vec![0_u8; 700 * 1024];
    rng().fill_bytes(&mut original);
    let name = "private launch plans.bin";

    let file_id = alice.send_file(&bob_id, name, &original).await.unwrap();
    let events = bob.poll_once().await.unwrap();
    assert!(matches!(
        events.as_slice(),
        [InboxEvent::FileOffer { file_id: offered, name: offered_name, size, .. }]
            if *offered == file_id && offered_name == name && *size == original.len() as u64
    ));

    let downloaded_at: Option<i64> = server
        .db()
        .query_row(
            "SELECT downloaded_at FROM file_refs WHERE file_id=?1 AND recipient=?2",
            rusqlite::params![file_id, bob_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(downloaded_at, None, "delivery must not count as download");

    // A registered third party is not authorized by mere knowledge of file_id.
    let carol_token = register_raw(&server).await;
    let carol = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    for suffix in ["chunk/0", "meta", "ack-download"] {
        let request = if suffix == "ack-download" {
            carol.post(format!(
                "{}/api/v1/files/{file_id}/{suffix}",
                server.base_url
            ))
        } else {
            carol.get(format!(
                "{}/api/v1/files/{file_id}/{suffix}",
                server.base_url
            ))
        };
        let response = request.bearer_auth(&carol_token).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{suffix}");
    }

    let (downloaded_name, bytes) = bob.download_file(&file_id).await.unwrap();
    assert_eq!(downloaded_name, name);
    assert_eq!(bytes, original);
    let downloaded_at: Option<i64> = server
        .db()
        .query_row(
            "SELECT downloaded_at FROM file_refs WHERE file_id=?1 AND recipient=?2",
            rusqlite::params![file_id, bob_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(downloaded_at.is_some(), "download must be acknowledged");

    let (repeated_name, repeated) = bob.download_file(&file_id).await.unwrap();
    assert_eq!(repeated_name, name);
    assert_eq!(repeated, original);
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_file_is_rejected_before_upload_or_local_pending_state() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let (mut alice, _bob, _alice_id, bob_id) = paired_clients(&temp, &server).await;
    assert!(matches!(
        alice.send_file(&bob_id, "empty", b"").await,
        Err(EngineError::EmptyFile)
    ));
    let pending: i64 = Connection::open(temp.path().join("alice.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM pending_uploads", [], |row| row.get(0))
        .unwrap();
    assert_eq!(pending, 0);
    let files: i64 = server
        .db()
        .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
        .unwrap();
    assert_eq!(files, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn server_authored_file_evicted_notice_is_advisory_and_not_session_decrypted() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let (_alice, mut bob, alice_id, bob_id) = paired_clients(&temp, &server).await;
    let file_id = "a".repeat(64);
    let payload = B64.encode(serde_json::to_vec(&json!({"file_id": file_id})).unwrap());
    let connection = server.db();
    let transaction = connection.unchecked_transaction().unwrap();
    transaction
        .execute(
            "INSERT INTO mailboxes(owner_id,seq,from_id,kind,payload,ts)
             SELECT ?1,COALESCE(last_seq,0)+1,?2,'file_evicted',?3,0 FROM owner_seq WHERE owner_id=?1",
            rusqlite::params![bob_id, alice_id, B64.decode(&payload).unwrap()],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE owner_seq SET last_seq=last_seq+1 WHERE owner_id=?1",
            [&bob_id],
        )
        .unwrap();
    transaction.commit().unwrap();
    let stored: (String, Vec<u8>) = connection
        .query_row(
            "SELECT kind,payload FROM mailboxes WHERE owner_id=?1 ORDER BY seq DESC LIMIT 1",
            [&bob_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored.0, "file_evicted");
    assert_eq!(B64.encode(stored.1), payload);
    drop(connection);

    assert!(matches!(
        bob.poll_once().await.unwrap().as_slice(),
        [InboxEvent::FileUnavailable { file_id: unavailable }] if *unavailable == file_id
    ));
}
