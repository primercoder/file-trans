use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey as _};
use kite_core::{
    ApiClient, Engine, EngineError, FileKey, Identity, InboxEvent, encrypt_file, generate_spk,
};
use rand::{RngCore as _, rng};
use reqwest::StatusCode;
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const CHUNK_SIZE: usize = 256 * 1024 - 16;

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
        let server_binary = std::env::var("CARGO_BIN_EXE_kite-server")
            .expect("run with the workspace test harness providing kite-server's binary path");
        let child = Command::new(server_binary)
            .env("KITE_BIND", address.to_string())
            .env("KITE_DB_PATH", temp.path().join("server.db"))
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

async fn paired_clients(
    temp: &TempDir,
    server: &TestServer,
) -> (Engine, Engine, String, String, String) {
    let mut alice = engine(temp, "alice", server);
    let mut bob = engine(temp, "bob", server);
    alice.register("Alice", "alice-hardware").await.unwrap();
    bob.register("Bob", "bob-hardware").await.unwrap();
    let alice_token = identity_token(temp, "alice");
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
    (alice, bob, alice_token, alice_id, bob_id)
}

fn identity_token(temp: &TempDir, name: &str) -> String {
    Connection::open(temp.path().join(format!("{name}.db")))
        .unwrap()
        .query_row("SELECT token FROM identity WHERE id=1", [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn api(server: &TestServer) -> ApiClient {
    ApiClient::new(&server.base_url, &server.fingerprint).unwrap()
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
    response.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn raw_status(server: &TestServer, token: &str, upload_id: &str) -> reqwest::Response {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!(
            "{}/api/v1/files/{upload_id}/status",
            server.base_url
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

fn pending_count(temp: &TempDir) -> i64 {
    Connection::open(temp.path().join("alice.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM pending_uploads", [], |row| row.get(0))
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn resume_uploads_only_missing_chunks_and_recipient_downloads_original() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let (mut alice, mut bob, token, _alice_id, bob_id) = paired_clients(&temp, &server).await;
    let mut original = vec![0_u8; CHUNK_SIZE * 2 + 777];
    rng().fill_bytes(&mut original);
    let fk = FileKey::generate().unwrap();
    let (header, chunks) = encrypt_file(&fk, &*original, CHUNK_SIZE).unwrap();
    assert_eq!(header.total_chunks, 3);
    let size = chunks
        .iter()
        .map(|chunk| chunk.ciphertext.len() as u64)
        .sum();
    let (file_id, upload_id) = api(&server)
        .init_file(&token, size, header.total_chunks)
        .await
        .unwrap();
    Connection::open(temp.path().join("alice.db"))
        .unwrap()
        .execute(
            "INSERT INTO pending_uploads(content_hash,upload_id,file_id,peer,name,size,fk,header,created_at)
             VALUES(?1,?2,?3,?4,'resume.bin',?5,?6,?7,1)",
            rusqlite::params![Sha256::digest(&original).as_slice(), upload_id, file_id,
                bob_id, original.len() as i64, fk.to_bytes().as_slice(), bincode::serialize(&header).unwrap()],
        )
        .unwrap();
    for index in [0, 2] {
        api(&server)
            .upload_file_chunk(
                &token,
                &upload_id,
                index,
                &chunks[index as usize].ciphertext,
            )
            .await
            .unwrap();
    }

    let status = api(&server)
        .file_upload_status(&token, &upload_id)
        .await
        .unwrap();
    assert_eq!(status.received, vec![0, 2]);
    assert_eq!(status.status, "uploading");
    alice
        .resume_upload(&file_id, &upload_id, &original)
        .await
        .unwrap();
    assert_eq!(pending_count(&temp), 0);
    bob.poll_once().await.unwrap();
    assert_eq!(bob.download_file(&file_id).await.unwrap().1, original);
}

#[tokio::test(flavor = "multi_thread")]
async fn resume_after_server_complete_resends_offer_and_clears_recovery_intent() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let (mut alice, mut bob, token, _alice_id, bob_id) = paired_clients(&temp, &server).await;
    let mut original = vec![0_u8; CHUNK_SIZE * 2 + 17];
    rng().fill_bytes(&mut original);
    let fk = FileKey::generate().unwrap();
    let (header, chunks) = encrypt_file(&fk, &*original, CHUNK_SIZE).unwrap();
    let size = chunks
        .iter()
        .map(|chunk| chunk.ciphertext.len() as u64)
        .sum();
    let (file_id, upload_id) = api(&server).init_file(&token, size, 3).await.unwrap();
    Connection::open(temp.path().join("alice.db"))
        .unwrap()
        .execute(
            "INSERT INTO pending_uploads(content_hash,upload_id,file_id,peer,name,size,fk,header,created_at)
             VALUES(?1,?2,?3,?4,'complete.bin',?5,?6,?7,1)",
            rusqlite::params![Sha256::digest(&original).as_slice(), upload_id, file_id,
                bob_id, original.len() as i64, fk.to_bytes().as_slice(), bincode::serialize(&header).unwrap()],
        )
        .unwrap();
    for chunk in &chunks {
        api(&server)
            .upload_file_chunk(&token, &upload_id, chunk.index, &chunk.ciphertext)
            .await
            .unwrap();
    }
    for chunk in &chunks {
        api(&server)
            .upload_file_chunk(&token, &upload_id, chunk.index, &chunk.ciphertext)
            .await
            .unwrap();
    }
    // Model a crash after complete but before offer delivery: the local intent remains.
    api(&server)
        .complete_file(&token, &upload_id)
        .await
        .unwrap();
    assert_eq!(pending_count(&temp), 1);

    alice
        .resume_upload(&file_id, &upload_id, &original)
        .await
        .unwrap();
    assert_eq!(pending_count(&temp), 0);
    assert!(matches!(
        bob.poll_once().await.unwrap().as_slice(),
        [InboxEvent::FileOffer { file_id: offered, .. }] if *offered == file_id
    ));
    assert_eq!(bob.download_file(&file_id).await.unwrap().1, original);
}

#[tokio::test(flavor = "multi_thread")]
async fn status_is_owner_only_and_unknown_upload_is_not_found() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let (_alice, _bob, token, _alice_id, _bob_id) = paired_clients(&temp, &server).await;
    let (_file_id, upload_id) = api(&server)
        .init_file(&token, 2 * 256 * 1024 + 16, 3)
        .await
        .unwrap();
    for index in [2, 0] {
        api(&server)
            .upload_file_chunk(&token, &upload_id, index, &[index as u8; 16])
            .await
            .unwrap();
    }
    let response = raw_status(&server, &token, &upload_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap()["received"],
        json!([0, 2])
    );

    let carol_token = register_raw(&server).await;
    assert_eq!(
        raw_status(&server, &carol_token, &upload_id).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        raw_status(&server, &token, &"0".repeat(64)).await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn resume_unknown_upload_returns_structured_error() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let (mut alice, _bob, _token, _alice_id, _bob_id) = paired_clients(&temp, &server).await;
    let error = alice
        .resume_upload(&"1".repeat(64), &"0".repeat(64), b"content")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        EngineError::UploadUnknown { ref upload_id } if *upload_id == "0".repeat(64)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn send_file_retry_resumes_pending_content_without_second_init() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let (mut alice, _bob, token, alice_id, bob_id) = paired_clients(&temp, &server).await;
    let original = vec![42_u8; CHUNK_SIZE * 2 + 99];
    let fk = FileKey::generate().unwrap();
    let (header, chunks) = encrypt_file(&fk, &*original, CHUNK_SIZE).unwrap();
    let size = chunks
        .iter()
        .map(|chunk| chunk.ciphertext.len() as u64)
        .sum();
    let (file_id, upload_id) = api(&server).init_file(&token, size, 3).await.unwrap();
    api(&server)
        .upload_file_chunk(&token, &upload_id, 1, &chunks[1].ciphertext)
        .await
        .unwrap();
    // Model a restart after init/chunk delivery but before send_file completed.
    Connection::open(temp.path().join("alice.db"))
        .unwrap()
        .execute(
            "INSERT INTO pending_uploads(content_hash,upload_id,file_id,peer,name,size,fk,header,created_at)
             VALUES(?1,?2,?3,?4,'retry.bin',?5,?6,?7,1)",
            rusqlite::params![Sha256::digest(&original).as_slice(), upload_id, file_id, bob_id,
                original.len() as i64, fk.to_bytes().as_slice(), bincode::serialize(&header).unwrap()],
        )
        .unwrap();

    assert_eq!(
        alice
            .send_file(&bob_id, "retry.bin", &original)
            .await
            .unwrap(),
        file_id
    );
    assert_eq!(pending_count(&temp), 0);
    let uploads: i64 = server
        .db()
        .query_row(
            "SELECT COUNT(*) FROM files WHERE owner=?1",
            [&alice_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(uploads, 1);
}
