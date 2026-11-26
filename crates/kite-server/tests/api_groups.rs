use std::time::{SystemTime, UNIX_EPOCH};

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

async fn sync(server: &Server, device: &Device) -> Vec<Value> {
    server
        .client
        .get(format!("{}/api/v1/sync?since=0", server.base))
        .bearer_auth(&device.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn group_create_list_add_and_fanout() {
    let server = spawn_server().await;
    let alice = register(&server, "alice").await;
    let bob = register(&server, "bob").await;
    let carol = register(&server, "carol").await;

    let created: Value = server
        .client
        .post(format!("{}/api/v1/groups", server.base))
        .bearer_auth(&alice.token)
        .json(&json!({"name": "team", "members": [&bob.id, &carol.id]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let group_id = created["group_id"].as_str().unwrap().to_owned();
    assert_eq!(created["members"].as_array().unwrap().len(), 3);

    let listed: Value = server
        .client
        .get(format!("{}/api/v1/groups", server.base))
        .bearer_auth(&bob.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed[0]["group_id"].as_str(), Some(group_id.as_str()));

    // Only the owner may add members.
    let dave = register(&server, "dave").await;
    let forbidden = server
        .client
        .post(format!("{}/api/v1/groups/{group_id}/members", server.base))
        .bearer_auth(&bob.token)
        .json(&json!({"device_id": &dave.id}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(forbidden, StatusCode::FORBIDDEN);
    let added: Value = server
        .client
        .post(format!("{}/api/v1/groups/{group_id}/members", server.base))
        .bearer_auth(&alice.token)
        .json(&json!({"device_id": &dave.id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(added["members"].as_array().unwrap().len(), 4);

    // Group fan-out excludes the sender and carries the routing hint.
    let payload = B64.encode(b"ciphertext");
    let sent: Value = server
        .client
        .post(format!("{}/api/v1/groups/{group_id}/send", server.base))
        .bearer_auth(&alice.token)
        .json(&json!({"payload": payload, "ts": now()}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(sent["delivered"], 3);

    for device in [&bob, &carol, &dave] {
        let entries = sync(&server, device).await;
        let entry = entries
            .iter()
            .find(|entry| entry["kind"] == "group_msg")
            .expect("group message");
        assert_eq!(entry["group_id"].as_str(), Some(group_id.as_str()));
        assert_eq!(entry["from"].as_str(), Some(alice.id.as_str()));
    }
    let alice_entries = sync(&server, &alice).await;
    assert!(alice_entries.iter().all(|entry| entry["kind"] != "group_msg"));

    // Non-members cannot send.
    let outsider = register(&server, "outsider").await;
    let denied = server
        .client
        .post(format!("{}/api/v1/groups/{group_id}/send", server.base))
        .bearer_auth(&outsider.token)
        .json(&json!({"payload": payload, "ts": now()}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(denied, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unknown_member_and_unknown_group_are_rejected() {
    let server = spawn_server().await;
    let alice = register(&server, "alice").await;
    let created: Value = server
        .client
        .post(format!("{}/api/v1/groups", server.base))
        .bearer_auth(&alice.token)
        .json(&json!({"name": "tiny", "members": [alice.id]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created["members"].as_array().unwrap().len(), 1);

    let missing_member = server
        .client
        .post(format!("{}/api/v1/groups", server.base))
        .bearer_auth(&alice.token)
        .json(&json!({"name": "bad", "members": ["no-such-device"]}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(missing_member, StatusCode::NOT_FOUND);

    let missing_group = server
        .client
        .post(format!("{}/api/v1/groups/no-such-group/send", server.base))
        .bearer_auth(&alice.token)
        .json(&json!({"payload": B64.encode(b"x"), "ts": now()}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(missing_group, StatusCode::FORBIDDEN);
}
