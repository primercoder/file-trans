use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use kite_core::{Engine, InboxEvent};
use rusqlite::Connection;
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

async fn pair(left: &mut Engine, right: &mut Engine) {
    let right_id = right.device_id().to_owned();
    let left_id = left.device_id().to_owned();
    left.start_pairing(&right_id).await.unwrap();
    let events = right.poll_once().await.unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, InboxEvent::PairRequest { from, .. } if from == &left_id)),
        "expected pair request, got {events:?}"
    );
    right.confirm_pairing(&left_id).await.unwrap();
    let events = left.poll_once().await.unwrap();
    assert!(
        events.iter().any(
            |event| matches!(event, InboxEvent::PairResponse { from, accepted } if from == &right_id && *accepted)
        ),
        "expected accepted pair response, got {events:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn group_create_key_distribution_messaging_and_replay() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let mut alice = engine(&temp, "alice", &server);
    let mut bob = engine(&temp, "bob", &server);
    let mut carol = engine(&temp, "carol", &server);
    alice.register("Alice", "alice-hw").await.unwrap();
    bob.register("Bob", "bob-hw").await.unwrap();
    carol.register("Carol", "carol-hw").await.unwrap();
    let alice_id = alice.device_id().to_owned();
    let bob_id = bob.device_id().to_owned();
    let carol_id = carol.device_id().to_owned();

    pair(&mut alice, &mut bob).await;
    pair(&mut alice, &mut carol).await;

    let group = alice
        .create_group("team", &[bob_id.clone(), carol_id.clone()])
        .await
        .unwrap();
    assert_eq!(group.members.len(), 3);
    let group_id = group.group_id.clone();

    for member in [&mut bob, &mut carol] {
        let events = member.poll_once().await.unwrap();
        assert!(
            events.iter().any(
                |event| matches!(event, InboxEvent::GroupReady { group_id: ready } if ready == &group_id)
            ),
            "expected group key, got {events:?}"
        );
    }

    alice.send_group_message(&group_id, "hello team").await.unwrap();
    // Capture the fan-out ciphertext before the recipients ACK it.
    let connection = Connection::open(server._temp.path().join("server.db")).unwrap();
    let (payload, from): (Vec<u8>, String) = connection
        .query_row(
            "SELECT payload,from_id FROM mailboxes WHERE owner_id=?1 AND kind='group_msg' ORDER BY seq DESC LIMIT 1",
            [&bob_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    drop(connection);

    for member in [&mut bob, &mut carol] {
        let events = member.poll_once().await.unwrap();
        let text = events
            .iter()
            .find_map(|event| match event {
                InboxEvent::GroupMessage { group_id: id, text, .. } if id == &group_id => {
                    Some(text.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("expected group message, got {events:?}"));
        assert_eq!(text, "hello team");
    }

    // The sender must not receive their own group fan-out.
    let events = alice.poll_once().await.unwrap();
    assert!(!events
        .iter()
        .any(|event| matches!(event, InboxEvent::GroupMessage { .. })));

    // Replaying the captured ciphertext must not produce a second event.
    let connection = Connection::open(server._temp.path().join("server.db")).unwrap();
    let transaction = connection.unchecked_transaction().unwrap();
    transaction
        .execute(
            "INSERT INTO mailboxes(owner_id,seq,from_id,kind,payload,ts,group_id)
             SELECT ?1,COALESCE(MAX(seq),0)+1,?2,'group_msg',?3,?4,?5 FROM mailboxes WHERE owner_id=?1",
            rusqlite::params![bob_id, from, payload, 0_i64 + now(), group_id],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE owner_seq SET last_seq = last_seq + 1 WHERE owner_id=?1",
            [&bob_id],
        )
        .unwrap();
    transaction.commit().unwrap();
    let events = bob.poll_once().await.unwrap();
    assert!(!events
        .iter()
        .any(|event| matches!(event, InboxEvent::GroupMessage { .. })));
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
