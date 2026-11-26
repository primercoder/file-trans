use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use kite_core::{Engine, InboxEvent};
use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;

struct TestServer {
    base_url: String,
    fingerprint: String,
    child: Child,
    _temp: TempDir,
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
            _temp: temp,
        }
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

fn inject_mail(server: &TestServer, owner: &str, from: &str, kind: &str, payload: Vec<u8>) {
    let connection = Connection::open(server._temp.path().join("server.db")).unwrap();
    connection.busy_timeout(Duration::from_secs(2)).unwrap();
    let transaction = connection.unchecked_transaction().unwrap();
    transaction
        .execute(
            "INSERT INTO mailboxes(owner_id,seq,from_id,kind,payload,ts)
         SELECT ?1,COALESCE(last_seq,0)+1,?2,?3,?4,0 FROM owner_seq WHERE owner_id=?1",
            rusqlite::params![owner, from, kind, payload],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE owner_seq SET last_seq=last_seq+1 WHERE owner_id=?1",
            [owner],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn only_message(events: Vec<InboxEvent>) -> String {
    match events.as_slice() {
        [InboxEvent::Message { text, .. }] => text.clone(),
        other => panic!("expected one message, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_messaging_offline_delivery_and_restart() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let mut alice = engine(&temp, "alice", &server);
    let mut bob = engine(&temp, "bob", &server);
    alice.register("Alice", "alice-hardware").await.unwrap();
    bob.register("Bob", "bob-hardware").await.unwrap();
    let connection = Connection::open(server._temp.path().join("server.db")).unwrap();
    let hw_hash: String = connection
        .query_row(
            "SELECT hw_hash FROM devices WHERE device_id=?1",
            [alice.device_id()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        hw_hash.starts_with("$argon2id$"),
        "raw hardware id must never be stored"
    );
    drop(connection);
    let alice_id = alice.device_id().to_owned();
    let bob_id = bob.device_id().to_owned();

    let devices = alice.refresh_devices().await.unwrap();
    assert!(devices.iter().any(|device| device.device_id == bob_id));
    let devices = bob.refresh_devices().await.unwrap();
    assert!(devices.iter().any(|device| device.device_id == alice_id));

    alice.start_pairing(&bob_id).await.unwrap();
    assert!(alice.send_message(&bob_id, "too early").await.is_err());
    let connection = Connection::open(server._temp.path().join("server.db")).unwrap();
    let raw_payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM mailboxes WHERE kind='pair_req'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!raw_payload.windows(5).any(|window| window == b"Alice"));
    let wire: Value = serde_json::from_slice(&raw_payload).unwrap();
    let encrypted_body = B64.decode(wire["body"].as_str().unwrap()).unwrap();
    assert!(!encrypted_body.windows(5).any(|window| window == b"Alice"));
    drop(connection);
    let events = bob.poll_once().await.unwrap();
    assert!(matches!(
        events.as_slice(),
        [InboxEvent::PairRequest { from, name }] if *from == alice_id && name == "Alice"
    ));
    bob.confirm_pairing(&alice_id).await.unwrap();
    let events = alice.poll_once().await.unwrap();
    assert!(matches!(
        events.as_slice(),
        [InboxEvent::PairResponse { from, accepted: true }] if *from == bob_id
    ));

    // A poison entry must receive a durable failed disposition, not block the valid message after it.
    inject_mail(&server, &bob_id, &alice_id, "msg", b"not-base64!".to_vec());
    alice.send_message(&bob_id, "hello1").await.unwrap();
    assert_eq!(only_message(bob.poll_once().await.unwrap()), "hello1");
    bob.send_message(&alice_id, "hello back").await.unwrap();
    assert_eq!(only_message(alice.poll_once().await.unwrap()), "hello back");

    for text in ["offline-1", "offline-2", "offline-3"] {
        alice.send_message(&bob_id, text).await.unwrap();
    }
    let events = bob.poll_once().await.unwrap();
    let texts: Vec<_> = events
        .into_iter()
        .map(|event| match event {
            InboxEvent::Message { text, .. } => text,
            other => panic!("unexpected event: {other:?}"),
        })
        .collect();
    assert_eq!(texts, ["offline-1", "offline-2", "offline-3"]);

    drop(alice);
    drop(bob);
    let mut alice = engine(&temp, "alice", &server);
    let mut bob = engine(&temp, "bob", &server);
    alice.send_message(&bob_id, "after restart").await.unwrap();
    assert_eq!(
        only_message(bob.poll_once().await.unwrap()),
        "after restart"
    );
    bob.send_message(&alice_id, "restart reply").await.unwrap();
    assert_eq!(
        only_message(alice.poll_once().await.unwrap()),
        "restart reply"
    );

    // Re-registration preserves existing sessions while a third party uses the new bundle.
    bob.register("Bob renewed", "bob-hardware").await.unwrap();
    let mut carol = engine(&temp, "carol", &server);
    carol.register("Carol", "carol-hardware").await.unwrap();
    carol.start_pairing(&bob_id).await.unwrap();
    assert!(matches!(
        bob.poll_once().await.unwrap().as_slice(),
        [InboxEvent::PairRequest { .. }]
    ));
    bob.confirm_pairing(carol.device_id()).await.unwrap();
    assert!(matches!(
        carol.poll_once().await.unwrap().as_slice(),
        [InboxEvent::PairResponse { accepted: true, .. }]
    ));
    carol.send_message(&bob_id, "new bundle").await.unwrap();
    assert_eq!(only_message(bob.poll_once().await.unwrap()), "new bundle");
    alice.send_message(&bob_id, "old session").await.unwrap();
    assert!(
        bob.poll_once().await.unwrap().iter().any(
            |event| matches!(event, InboxEvent::Message { text, .. } if text == "old session")
        )
    );

    // Replay the exact original request: no event and no replacement of Alice's session.
    inject_mail(&server, &bob_id, &alice_id, "pair_req", raw_payload);
    assert!(bob.poll_once().await.unwrap().is_empty());
    alice
        .send_message(&bob_id, "existing session survives replay")
        .await
        .unwrap();
    assert_eq!(
        only_message(bob.poll_once().await.unwrap()),
        "existing session survives replay"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_sides_agree_on_a_safety_number() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let mut alice = engine(&temp, "alice", &server);
    let mut bob = engine(&temp, "bob", &server);
    alice.register("Alice", "a").await.unwrap();
    bob.register("Bob", "b").await.unwrap();
    let bob_id = bob.device_id().to_owned();
    let alice_id = alice.device_id().to_owned();

    assert!(
        alice.safety_number(&bob_id).unwrap().is_none(),
        "unpaired peers have no safety number"
    );

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

    let alice_code = alice.safety_number(&bob_id).unwrap().expect("code");
    let bob_code = bob.safety_number(&alice_id).unwrap().expect("code");
    assert_eq!(alice_code, bob_code);
    assert_eq!(alice_code.len(), 60);
}

#[tokio::test(flavor = "multi_thread")]
async fn compromised_server_cannot_substitute_a_peer_bundle() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let mut alice = engine(&temp, "alice", &server);
    let mut bob = engine(&temp, "bob", &server);
    let mut mallory = engine(&temp, "mallory", &server);
    alice.register("Alice", "a").await.unwrap();
    bob.register("Bob", "b").await.unwrap();
    mallory.register("Mallory", "m").await.unwrap();
    let bob_id = bob.device_id().to_owned();
    let mallory_id = mallory.device_id().to_owned();

    // A server that controls its database can answer the bundle lookup for Bob's
    // device id with Mallory's keys. The client must detect the mismatch.
    let connection = Connection::open(server._temp.path().join("server.db")).unwrap();
    connection.busy_timeout(Duration::from_secs(2)).unwrap();
    connection
        .execute(
            "UPDATE devices SET
                 ik_pub=(SELECT ik_pub FROM devices WHERE device_id=?1),
                 spk=(SELECT spk FROM devices WHERE device_id=?1),
                 spk_sig=(SELECT spk_sig FROM devices WHERE device_id=?1)
             WHERE device_id=?2",
            rusqlite::params![mallory_id, bob_id],
        )
        .unwrap();
    connection
        .execute("DELETE FROM opk_pool WHERE owner_id=?1", [&bob_id])
        .unwrap();
    drop(connection);

    let error = alice.start_pairing(&bob_id).await.unwrap_err();
    assert!(
        matches!(&error, kite_core::EngineError::Protocol(message) if message.contains("bundle identity")),
        "expected bundle identity rejection, got {error:?}"
    );
    assert!(
        alice.paired_peers().unwrap().is_empty(),
        "a mismatched bundle must not persist a session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn consumed_opk_is_rejected_instead_of_downgrading_to_3dh() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let mut alice = engine(&temp, "alice", &server);
    let mut bob = engine(&temp, "bob", &server);
    alice.register("Alice", "a").await.unwrap();
    bob.register("Bob", "b").await.unwrap();
    let bob_id = bob.device_id().to_owned();
    alice.start_pairing(&bob_id).await.unwrap();
    let connection = Connection::open(server._temp.path().join("server.db")).unwrap();
    connection.busy_timeout(Duration::from_secs(2)).unwrap();
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM mailboxes WHERE kind='pair_req'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        bob.poll_once().await.unwrap().as_slice(),
        [InboxEvent::PairRequest { .. }]
    ));
    let connection = Connection::open(temp.path().join("bob.db")).unwrap();
    // Isolate this request from the existing-session rule; OPK 0 is nevertheless consumed.
    connection.execute("DELETE FROM sessions", []).unwrap();
    connection
        .execute("DELETE FROM pending_pairing", [])
        .unwrap();
    connection
        .execute("DELETE FROM handshake_nonces", [])
        .unwrap();
    drop(connection);
    let wire: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(wire["used_opk_id"], 0);
    let forged = serde_json::json!({
        "version": 1, "ik_pub": wire["ik_pub"], "ek_pub": B64.encode([77_u8; 32]),
        "used_opk_id": 0, "body": "AA==",
    });
    inject_mail(
        &server,
        &bob_id,
        alice.device_id(),
        "pair_req",
        serde_json::to_vec(&forged).unwrap(),
    );
    assert!(bob.poll_once().await.unwrap().is_empty());
    let connection = Connection::open(temp.path().join("bob.db")).unwrap();
    let sessions: i64 = connection
        .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        sessions, 0,
        "a named unavailable OPK must not create a 3DH session"
    );
}
