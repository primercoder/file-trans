use std::{
    fs,
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use kite_core::{Engine, EngineError, InboxEvent};
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
        let server_binary = std::env::var("CARGO_BIN_EXE_kite-server").unwrap();
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

fn engine(path: &str, server: &TestServer) -> Engine {
    Engine::open(path, &server.base_url, &server.fingerprint).unwrap()
}

fn import(path: &str, passphrase: &str, blob: &[u8], server: &TestServer) -> Engine {
    Engine::import_identity(
        path,
        &server.base_url,
        &server.fingerprint,
        passphrase,
        blob,
    )
    .unwrap()
}

fn only_message(events: Vec<InboxEvent>) -> String {
    match events.as_slice() {
        [InboxEvent::Message { text, .. }] => text.clone(),
        other => panic!("expected one message, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_preserves_identity_and_ratchet_in_both_directions() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let mut alice = engine(&temp.path().join("alice.db").to_string_lossy(), &server);
    let mut bob = engine(&temp.path().join("bob.db").to_string_lossy(), &server);
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
        [InboxEvent::PairResponse { .. }]
    ));
    alice
        .send_message(&bob_id, "before migration")
        .await
        .unwrap();
    assert_eq!(
        only_message(bob.poll_once().await.unwrap()),
        "before migration"
    );

    let blob = alice
        .export_identity("correct horse battery staple")
        .unwrap();
    let mut migrated = import(
        &temp.path().join("fresh-migrated.db").to_string_lossy(),
        "correct horse battery staple",
        &blob,
        &server,
    );
    assert_eq!(migrated.device_id(), alice_id);
    migrated
        .send_message(&bob_id, "from new device")
        .await
        .unwrap();
    assert_eq!(
        only_message(bob.poll_once().await.unwrap()),
        "from new device"
    );
    bob.send_message(&alice_id, "reply to new device")
        .await
        .unwrap();
    assert_eq!(
        only_message(migrated.poll_once().await.unwrap()),
        "reply to new device"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn import_rejects_nonempty_store_without_changing_identity_or_session() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let alice_path = temp.path().join("alice.db");
    let mut alice = engine(&alice_path.to_string_lossy(), &server);
    let mut bob = engine(&temp.path().join("bob.db").to_string_lossy(), &server);
    let mut source = engine(&temp.path().join("source.db").to_string_lossy(), &server);
    alice.register("Alice", "alice-hardware").await.unwrap();
    bob.register("Bob", "bob-hardware").await.unwrap();
    source.register("Source", "source-hardware").await.unwrap();
    let alice_id = alice.device_id().to_owned();
    let bob_id = bob.device_id().to_owned();
    alice.start_pairing(&bob_id).await.unwrap();
    bob.poll_once().await.unwrap();
    bob.confirm_pairing(&alice_id).await.unwrap();
    alice.poll_once().await.unwrap();
    let blob = source.export_identity("secret").unwrap();

    let error = Engine::import_identity(
        &alice_path,
        &server.base_url,
        &server.fingerprint,
        "secret",
        &blob,
    )
    .err()
    .unwrap();
    assert!(matches!(error, EngineError::BackupTargetNotEmpty));
    assert_eq!(alice.device_id(), alice_id);
    alice
        .send_message(&bob_id, "original session intact")
        .await
        .unwrap();
    assert_eq!(
        only_message(bob.poll_once().await.unwrap()),
        "original session intact"
    );
}

#[test]
fn wrong_passphrase_and_tampering_have_distinct_errors() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let original = engine(&temp.path().join("original.db").to_string_lossy(), &server);
    let blob = original.export_identity("secret").unwrap();
    let path = temp.path().join("other.db").to_string_lossy().to_string();
    let error =
        Engine::import_identity(&path, &server.base_url, &server.fingerprint, "wrong", &blob)
            .err()
            .unwrap();
    assert!(matches!(error, EngineError::BackupAuthentication));

    let mut tampered = blob;
    let last = tampered.last_mut().unwrap();
    *last ^= 1;
    let error = Engine::import_identity(
        &path,
        &server.base_url,
        &server.fingerprint,
        "secret",
        &tampered,
    )
    .err()
    .unwrap();
    assert!(matches!(error, EngineError::BackupAuthentication));
}

#[test]
fn bad_magic_version_and_truncation_are_bad_format() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let original = engine(&temp.path().join("original.db").to_string_lossy(), &server);
    let blob = original.export_identity("secret").unwrap();
    let path = temp.path().join("other.db").to_string_lossy().to_string();
    for index in [0, 13] {
        let mut damaged = blob.clone();
        damaged[index] ^= 1;
        let error = Engine::import_identity(
            &path,
            &server.base_url,
            &server.fingerprint,
            "secret",
            &damaged,
        )
        .err()
        .unwrap();
        assert!(matches!(error, EngineError::BackupBadFormat(_)));
    }
    for length in [0, 13, 14, 29, 41] {
        let error = Engine::import_identity(
            &path,
            &server.base_url,
            &server.fingerprint,
            "secret",
            &blob[..length],
        )
        .err()
        .unwrap();
        assert!(matches!(error, EngineError::BackupTruncated));
    }
}

#[test]
fn exports_use_fresh_randomness_and_empty_identities_round_trip() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let original = engine(&temp.path().join("original.db").to_string_lossy(), &server);
    let first = original.export_identity("secret").unwrap();
    let second = original.export_identity("secret").unwrap();
    assert_ne!(first, second);
    assert!(first.starts_with(b"KITE-BACKUP-V1"));
    for (index, blob) in [first, second].into_iter().enumerate() {
        let path = temp.path().join(format!("restored-{index}.db"));
        let restored = import(&path.to_string_lossy(), "secret", &blob, &server);
        assert_eq!(restored.device_id(), original.device_id());
    }
}
