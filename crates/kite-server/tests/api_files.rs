use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey};
use kite_core::Identity;
use rand::RngCore as _;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tempfile::TempDir;

struct Server {
    child: Child,
    client: reqwest::Client,
    base: String,
    _temp: TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

#[allow(clippy::zombie_processes)] // Server::drop kills and waits on every normal return path.
async fn spawn_server() -> Server {
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let client = client();
    let base = format!("https://127.0.0.1:{port}");
    for _ in 0..100 {
        if client.get(format!("{base}/healthz")).send().await.is_ok() {
            return Server {
                child,
                client,
                base,
                _temp: temp,
            };
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server did not become ready");
}

async fn register(server: &Server) -> String {
    let identity = Identity::generate();
    let id = identity.device_id();
    let (_private, spk, spk_sig) = kite_core::generate_spk(&identity);
    let signing_key = {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_pem(&identity.private_pem())
            .unwrap()
            .to_bytes()
    };
    let signing_key = SigningKey::from_bytes(&signing_key);
    let signature = signing_key.sign(format!("register||{id}||Alice").as_bytes());
    let response: Value = server
        .client
        .post(format!("{}/api/v1/register", server.base))
        .json(&json!({
            "device_id": id,
            "ik_pub": B64.encode(identity.ed25519_public_key()),
            "name": "Alice",
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
    response["token"].as_str().unwrap().to_owned()
}

async fn init(server: &Server, token: &str, size: usize, chunks: usize) -> Value {
    let response = server
        .client
        .post(format!("{}/api/v1/files/init", server.base))
        .bearer_auth(token)
        .json(&json!({"size": size, "chunks": chunks}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

async fn put_chunk(
    server: &Server,
    token: &str,
    upload_id: &str,
    index: usize,
    bytes: &[u8],
) -> StatusCode {
    server
        .client
        .put(format!(
            "{}/api/v1/files/{upload_id}/chunk/{index}",
            server.base
        ))
        .bearer_auth(token)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap()
        .status()
}

async fn complete(server: &Server, token: &str, upload_id: &str) -> StatusCode {
    server
        .client
        .post(format!("{}/api/v1/files/{upload_id}/complete", server.base))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn out_of_order_upload_complete_meta_and_binary_download() {
    let server = spawn_server().await;
    let token = register(&server).await;
    let unauthorized = server
        .client
        .post(format!("{}/api/v1/files/init", server.base))
        .json(&json!({"size": 12, "chunks": 3}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let chunks: Vec<Vec<u8>> = [262_144_usize, 262_144, 777]
        .into_iter()
        .map(|len| {
            let mut bytes = vec![0_u8; len];
            rand::rng().fill_bytes(&mut bytes);
            bytes
        })
        .collect();
    let size = chunks.iter().map(Vec::len).sum::<usize>();
    let upload = init(&server, &token, size, chunks.len()).await;
    let file_id = upload["file_id"].as_str().unwrap();
    let upload_id = upload["upload_id"].as_str().unwrap();
    assert_ne!(file_id, upload_id);

    for index in [2, 0, 1] {
        assert_eq!(
            put_chunk(&server, &token, upload_id, index, &chunks[index]).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        put_chunk(&server, &token, "0".repeat(64).as_str(), 0, b"bad").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(complete(&server, &token, upload_id).await, StatusCode::OK);

    let meta: Value = server
        .client
        .get(format!("{}/api/v1/files/{file_id}/meta", server.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(meta["size"], size);
    assert_eq!(meta["chunks"], chunks.len());

    for (index, expected) in chunks.iter().enumerate() {
        let response = server
            .client
            .get(format!(
                "{}/api/v1/files/{file_id}/chunk/{index}",
                server.base
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.bytes().await.unwrap().as_ref(), expected);
        assert_eq!(
            std::fs::read(
                server
                    ._temp
                    .path()
                    .join("files")
                    .join(file_id)
                    .join(format!("{index}.bin"))
            )
            .unwrap(),
            *expected
        );
    }

    let unknown = "f".repeat(64);
    for suffix in ["meta", "chunk/0"] {
        let response = server
            .client
            .get(format!("{}/api/v1/files/{unknown}/{suffix}", server.base))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn declared_size_and_chunk_count_are_enforced_without_persisting_excess_bytes() {
    let server = spawn_server().await;
    let token = register(&server).await;
    let upload = init(&server, &token, 1, 1).await;
    let upload_id = upload["upload_id"].as_str().unwrap();
    let file_id = upload["file_id"].as_str().unwrap();

    assert_eq!(
        put_chunk(&server, &token, upload_id, 0, b"too large").await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        complete(&server, &token, upload_id).await,
        StatusCode::CONFLICT
    );
    assert!(!server._temp.path().join("files").join(file_id).exists());
    let stats: Value = server
        .client
        .get(format!("{}/stats", server.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats["storage_used"], 1);

    for (size, chunks) in [(0, 0), (1, 0), (1, 2), (256 * 1024 + 1, 1)] {
        let response = server
            .client
            .post(format!("{}/api/v1/files/init", server.base))
            .bearer_auth(&token)
            .json(&json!({"size": size, "chunks": chunks}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_oversized_overwrites_keep_db_and_disk_in_lockstep() {
    let server = spawn_server().await;
    let token = register(&server).await;
    let upload = init(&server, &token, 5, 1).await;
    let upload_id = upload["upload_id"].as_str().unwrap();
    let file_id = upload["file_id"].as_str().unwrap();
    assert_eq!(
        put_chunk(&server, &token, upload_id, 0, b"valid").await,
        StatusCode::OK
    );

    let mut requests = Vec::new();
    for _ in 0..8 {
        let client = server.client.clone();
        let url = format!(
            "{}/api/v1/files/{upload_id}/chunk/0",
            server.base
        );
        let token = token.clone();
        requests.push(tokio::spawn(async move {
            client
                .put(url)
                .bearer_auth(token)
                .body(vec![7; 6])
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    let mut statuses = Vec::new();
    for request in requests {
        statuses.push(request.await.unwrap());
    }
    assert!(statuses.contains(&StatusCode::PAYLOAD_TOO_LARGE));

    let directory = server._temp.path().join("files").join(file_id);
    let disk: Vec<(u32, u64)> = std::fs::read_dir(&directory)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.strip_suffix(".bin").map(|index| {
                (
                    index.parse().unwrap(),
                    entry.metadata().unwrap().len(),
                )
            })
        })
        .collect();
    let connection = rusqlite::Connection::open(server._temp.path().join("kite.db")).unwrap();
    let stored: Vec<(u32, u64)> = connection
        .prepare("SELECT chunk_index,actual_bytes FROM file_chunks WHERE file_id=?1 ORDER BY chunk_index")
        .unwrap()
        .query_map([file_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(stored, disk);
    assert_eq!(stored, vec![(0, 5)]);
    assert_eq!(std::fs::read(directory.join("0.bin")).unwrap(), b"valid");
    let actual: u64 = connection
        .query_row("SELECT actual_bytes FROM files WHERE file_id=?1", [file_id], |row| row.get(0))
        .unwrap();
    assert_eq!(actual, 5);
}

#[tokio::test]
async fn completion_rejects_wrong_total_even_when_all_chunk_indexes_exist() {
    let server = spawn_server().await;
    let token = register(&server).await;
    let upload = init(&server, &token, 262_150, 2).await;
    let upload_id = upload["upload_id"].as_str().unwrap();
    assert_eq!(
        put_chunk(&server, &token, upload_id, 0, &vec![1; 262_144]).await,
        StatusCode::OK
    );
    assert_eq!(
        put_chunk(&server, &token, upload_id, 1, b"456").await,
        StatusCode::OK
    );
    assert_eq!(
        complete(&server, &token, upload_id).await,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn incomplete_upload_is_rejected_and_repeated_chunk_is_overwritten() {
    let server = spawn_server().await;
    let token = register(&server).await;
    let upload = init(&server, &token, 262_147, 2).await;
    let file_id = upload["file_id"].as_str().unwrap();
    let upload_id = upload["upload_id"].as_str().unwrap();

    assert_eq!(
        put_chunk(&server, &token, upload_id, 0, &vec![1; 262_144]).await,
        StatusCode::OK
    );
    assert_eq!(
        complete(&server, &token, upload_id).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        put_chunk(&server, &token, upload_id, 1, b"old").await,
        StatusCode::OK
    );
    assert_eq!(
        put_chunk(&server, &token, upload_id, 1, b"new").await,
        StatusCode::OK
    );
    assert_eq!(complete(&server, &token, upload_id).await, StatusCode::OK);

    let response = server
        .client
        .get(format!("{}/api/v1/files/{file_id}/chunk/1", server.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"new");
}
