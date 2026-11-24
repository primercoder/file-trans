use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use kite_core::{Engine, InboxEvent};
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
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let build = Command::new(env!("CARGO"))
            .args(["build", "-p", "kite-server"])
            .current_dir(&workspace)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(build.success());
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let server_binary = workspace.join("target").join(profile).join("kite-server");
        let child = Command::new(server_binary)
            .env("KITE_BIND", address.to_string())
            .env("KITE_DB_PATH", &db_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let fingerprint_path = temp.path().join("fingerprint.txt");
        let deadline = Instant::now() + Duration::from_secs(10);
        let fingerprint = loop {
            if let Ok(value) = fs::read_to_string(&fingerprint_path) {
                if !value.trim().is_empty() {
                    break value.trim().to_owned();
                }
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
    let alice_id = alice.device_id().to_owned();
    let bob_id = bob.device_id().to_owned();

    let devices = alice.refresh_devices().await.unwrap();
    assert!(devices.iter().any(|device| device.device_id == bob_id));
    let devices = bob.refresh_devices().await.unwrap();
    assert!(devices.iter().any(|device| device.device_id == alice_id));

    alice.start_pairing(&bob_id).await.unwrap();
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
}
