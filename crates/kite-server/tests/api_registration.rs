use std::{collections::HashSet, fs};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey};
use kite_core::Identity;
use reqwest::{StatusCode, tls::Certificate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct Device {
    identity: Identity,
    device_id: String,
    spk: [u8; 32],
    spk_sig: [u8; 64],
}

impl Device {
    fn new(name: &str) -> (Self, Value) {
        let identity = Identity::generate();
        let device_id = identity.device_id();
        let (_spk_private, spk, spk_sig) = kite_core::generate_spk(&identity);
        let ik = identity.ed25519_public_key();
        let signing_key = SigningKey::from_bytes(&test_signing_key(&identity));
        let sig = signing_key.sign(format!("register||{device_id}||{name}").as_bytes());
        let device = Self {
            identity,
            device_id: device_id.clone(),
            spk,
            spk_sig,
        };
        let body = json!({
            "device_id": device_id,
            "ik_pub": B64.encode(ik),
            "name": name,
            "hw_hash": "test-hardware",
            "spk": B64.encode(spk),
            "spk_sig": B64.encode(spk_sig),
            "opks": [],
            "sig": hex::encode(sig.to_bytes()),
        });
        (device, body)
    }
}

struct Server {
    base: String,
    client: reqwest::Client,
    _temp: TempDir,
}

async fn spawn_server() -> Server {
    spawn_server_with_grace(std::time::Duration::from_secs(90)).await
}

async fn spawn_server_with_grace(online_grace: std::time::Duration) -> Server {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("kite.db");
    let mut state = kite_server::state::AppState::new(kite_server::db::Db::open(&db_path).unwrap());
    state.online_grace = online_grace;
    let app = kite_server::router(state);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let tls = kite_server::tls::self_signed().await.unwrap();
    let printed_fingerprint = tls.fingerprint.clone();
    let cert_der = tls.cert_der.clone();
    kite_server::tls::write_fingerprint(&db_path, &printed_fingerprint).unwrap();
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls.config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    let file_fingerprint = fs::read_to_string(temp.path().join("fingerprint.txt")).unwrap();
    assert_eq!(file_fingerprint.trim(), printed_fingerprint);
    assert_eq!(hex::encode(Sha256::digest(&cert_der)), printed_fingerprint);
    let client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_der(&cert_der).unwrap())
        .build()
        .unwrap();
    Server {
        base: format!("https://{addr}"),
        client,
        _temp: temp,
    }
}

fn test_signing_key(identity: &Identity) -> [u8; 32] {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    SigningKey::from_pkcs8_pem(&identity.private_pem())
        .unwrap()
        .to_bytes()
}

async fn register(server: &Server, body: &Value) -> (StatusCode, Value) {
    let response = server
        .client
        .post(format!("{}/api/v1/register", server.base))
        .json(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.json().await.unwrap();
    (status, body)
}

#[tokio::test]
async fn registration_login_directory_and_opk_lifecycle() {
    let server = spawn_server().await;
    let (a, a_body) = Device::new("Alice");
    let mut fake_registration = a_body.clone();
    fake_registration["sig"] = json!(hex::encode([0_u8; 64]));
    let (status, error) = register(&server, &fake_registration).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{error}");
    let (status, registered) = register(&server, &a_body).await;
    assert_eq!(status, StatusCode::OK, "{registered}");
    assert!(registered["token"].is_string());
    assert_eq!(registered["expires_at"], 0);

    let (status, repeat) = register(&server, &a_body).await;
    assert_eq!(status, StatusCode::OK, "{repeat}");
    let token_a = repeat["token"].as_str().unwrap();

    let (_, mut conflicting) = Device::new("Alice");
    conflicting["device_id"] = a_body["device_id"].clone();
    let (status, error) = register(&server, &conflicting).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert!(error["error"]["code"].is_string());

    let (_b, b_body) = Device::new("Bob");
    let (status, _) = register(&server, &b_body).await;
    assert_eq!(status, StatusCode::OK);

    let devices: Value = server
        .client
        .get(format!("{}/api/v1/devices", server.base))
        .bearer_auth(token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let devices = devices.as_array().unwrap();
    assert_eq!(devices.len(), 2);
    for (id, expected_online) in [(&a.device_id, true), (&_b.device_id, false)] {
        let device = devices.iter().find(|d| &d["device_id"] == id).unwrap();
        assert_eq!(device["online"], expected_online);
        assert!(device["last_seen"].is_i64() || device["last_seen"].is_u64());
    }
    let detail: Value = server
        .client
        .get(format!("{}/api/v1/devices/{}", server.base, a.device_id))
        .bearer_auth(token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["name"], "Alice");

    let opks: Vec<_> = (10..13)
        .map(|id| json!({"id": id, "key": B64.encode([id; 32])}))
        .collect();
    let status = server
        .client
        .put(format!("{}/api/v1/bundles/opks", server.base))
        .bearer_auth(token_a)
        .json(&json!({"opks": opks}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::OK);

    let mut ids = HashSet::new();
    for _ in 0..3 {
        let bundle: Value = server
            .client
            .get(format!("{}/api/v1/bundles/{}", server.base, a.device_id))
            .bearer_auth(token_a)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            B64.decode(bundle["ik"].as_str().unwrap()).unwrap(),
            a.identity.ed25519_public_key()
        );
        assert_eq!(B64.decode(bundle["spk"].as_str().unwrap()).unwrap(), a.spk);
        assert_eq!(
            B64.decode(bundle["spk_sig"].as_str().unwrap()).unwrap(),
            a.spk_sig
        );
        ids.insert(bundle["opk_id"].as_u64().unwrap());
        assert!(bundle["opk"].is_string());
    }
    assert_eq!(ids.len(), 3);
    let bundle: Value = server
        .client
        .get(format!("{}/api/v1/bundles/{}", server.base, a.device_id))
        .bearer_auth(token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(bundle.get("opk").is_none());
    assert!(bundle.get("opk_id").is_none());
}

#[tokio::test]
async fn authenticated_activity_expires_from_presence() {
    let server = spawn_server_with_grace(std::time::Duration::ZERO).await;
    let (device, body) = Device::new("Alice");
    let (_, registered) = register(&server, &body).await;
    let token = registered["token"].as_str().unwrap();
    let detail: Value = server
        .client
        .get(format!(
            "{}/api/v1/devices/{}",
            server.base, device.device_id
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        detail["online"], false,
        "zero grace makes even current activity expire at read"
    );
}

#[tokio::test]
async fn challenge_authentication_and_errors() {
    let server = spawn_server().await;
    let (device, body) = Device::new("Alice");
    register(&server, &body).await;

    let challenge: Value = server
        .client
        .post(format!("{}/api/v1/auth/challenge", server.base))
        .json(&json!({"device_id": device.device_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nonce = challenge["nonce"].as_str().unwrap();
    let signing_key = SigningKey::from_bytes(&test_signing_key(&device.identity));
    let sig = signing_key.sign(format!("{nonce}||{}", device.device_id).as_bytes());
    let verified: Value = server.client.post(format!("{}/api/v1/auth/verify", server.base))
        .json(&json!({"device_id": device.device_id, "nonce": nonce, "sig": hex::encode(sig.to_bytes())}))
        .send().await.unwrap().json().await.unwrap();
    assert!(verified["token"].is_string());

    let challenge: Value = server
        .client
        .post(format!("{}/api/v1/auth/challenge", server.base))
        .json(&json!({"device_id": device.device_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nonce = challenge["nonce"].as_str().unwrap();
    let fake = [0_u8; 64];
    let response = server
        .client
        .post(format!("{}/api/v1/auth/verify", server.base))
        .json(&json!({"device_id": device.device_id, "nonce": nonce, "sig": hex::encode(fake)}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"]["code"],
        "unauthorized"
    );

    assert_eq!(
        server
            .client
            .get(format!("{}/api/v1/devices", server.base))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = server
        .client
        .get(format!("{}/api/v1/bundles/nonexistent", server.base))
        .bearer_auth(verified["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let health: Value = server
        .client
        .get(format!("{}/healthz", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["version"], "0.1.0");
    assert!(health["uptime_s"].is_u64());
}
