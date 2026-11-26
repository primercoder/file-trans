use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

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
            rusqlite::params![bob_id, from, payload, now(), group_id],
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

fn identity_of(temp: &TempDir, name: &str) -> kite_core::Identity {
    let connection = Connection::open(temp.path().join(format!("{name}.db"))).unwrap();
    let pem: String = connection
        .query_row("SELECT private_pem FROM identity", [], |row| row.get(0))
        .unwrap();
    kite_core::Identity::from_private(&pem).unwrap()
}

fn group_key_of(temp: &TempDir, name: &str, group_id: &str) -> [u8; 32] {
    let connection = Connection::open(temp.path().join(format!("{name}.db"))).unwrap();
    let key: Vec<u8> = connection
        .query_row("SELECT key FROM group_keys WHERE group_id=?1", [group_id], |row| {
            row.get(0)
        })
        .unwrap();
    key.try_into().unwrap()
}

fn enqueue_group_message(server: &TestServer, owner: &str, from: &str, group_id: &str, payload: serde_json::Value) {
    let connection = Connection::open(server._temp.path().join("server.db")).unwrap();
    connection.busy_timeout(Duration::from_secs(2)).unwrap();
    let transaction = connection.unchecked_transaction().unwrap();
    transaction
        .execute(
            "INSERT INTO mailboxes(owner_id,seq,from_id,kind,payload,ts,group_id)
             SELECT ?1,COALESCE(MAX(seq),0)+1,?2,'group_msg',?3,?4,?5 FROM mailboxes WHERE owner_id=?1",
            rusqlite::params![owner, from, serde_json::to_vec(&payload).unwrap(), now(), group_id],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE owner_seq SET last_seq = last_seq + 1 WHERE owner_id=?1",
            [owner],
        )
        .unwrap();
    transaction.commit().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn group_messages_are_signed_and_forged_attributions_are_rejected() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let mut alice = engine(&temp, "alice", &server);
    let mut bob = engine(&temp, "bob", &server);
    let mut carol = engine(&temp, "carol", &server);
    alice.register("Alice", "a").await.unwrap();
    bob.register("Bob", "b").await.unwrap();
    carol.register("Carol", "c").await.unwrap();
    let _alice_id = alice.device_id().to_owned();
    let bob_id = bob.device_id().to_owned();
    let carol_id = carol.device_id().to_owned();
    pair(&mut alice, &mut bob).await;
    pair(&mut alice, &mut carol).await;

    let group = alice
        .create_group("team", &[bob_id.clone(), carol_id.clone()])
        .await
        .unwrap();
    let group_id = group.group_id.clone();
    for member in [&mut bob, &mut carol] {
        member.poll_once().await.unwrap();
    }

    alice.send_group_message(&group_id, "signed hello").await.unwrap();
    let connection = Connection::open(server._temp.path().join("server.db")).unwrap();
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM mailboxes WHERE owner_id=?1 AND kind='group_msg' ORDER BY seq DESC LIMIT 1",
            [&bob_id],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let wire: Value = serde_json::from_slice(&payload).unwrap();
    let signature = wire
        .get("sig_b64")
        .and_then(Value::as_str)
        .expect("group messages must carry a sender signature");
    assert_eq!(B64.decode(signature).unwrap().len(), 64);

    // Carol knows the group key but must not be able to speak as Bob: the
    // server is the only party that could misroute the sender field, and the
    // roster signature makes that useless.
    let key = group_key_of(&temp, "carol", &group_id);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = [7_u8; 12];
    let seq = 1_i64;
    let aad = format!("kite-group-v1|{group_id}|{bob_id}|{seq}").into_bytes();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: b"forged",
                aad: &aad,
            },
        )
        .unwrap();
    let carol_key = identity_of(&temp, "carol");
    let mut signed = aad.clone();
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(&ct);
    let sig = carol_key.sign_bytes(&signed);
    enqueue_group_message(
        &server,
        &carol_id,
        &bob_id,
        &group_id,
        serde_json::json!({
            "seq": seq,
            "nonce_b64": B64.encode(nonce),
            "ct_b64": B64.encode(&ct),
            "sig_b64": B64.encode(sig),
            "ts": now(),
        }),
    );

    let events = carol.poll_once().await.unwrap();
    assert!(
        !events.iter().any(|event| matches!(
            event,
            InboxEvent::GroupMessage { text, .. } if text == "forged"
        )),
        "a signature from another identity must not be accepted as Bob: {events:?}"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            InboxEvent::GroupMessage { text, .. } if text == "signed hello"
        )),
        "the genuine signed message must still be delivered: {events:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn group_roster_authenticates_members_that_are_not_paired_with_each_other() {
    let server = TestServer::spawn();
    let temp = tempfile::tempdir().unwrap();
    let mut alice = engine(&temp, "alice", &server);
    let mut bob = engine(&temp, "bob", &server);
    let mut carol = engine(&temp, "carol", &server);
    alice.register("Alice", "a").await.unwrap();
    bob.register("Bob", "b").await.unwrap();
    carol.register("Carol", "c").await.unwrap();
    let bob_id = bob.device_id().to_owned();
    let carol_id = carol.device_id().to_owned();

    // Star topology: Alice pairs with both, Bob and Carol never pair directly.
    pair(&mut alice, &mut bob).await;
    pair(&mut alice, &mut carol).await;
    let group = alice
        .create_group("team", &[bob_id.clone(), carol_id.clone()])
        .await
        .unwrap();
    let group_id = group.group_id.clone();
    for member in [&mut bob, &mut carol] {
        member.poll_once().await.unwrap();
    }
    assert!(
        bob.safety_number(&carol_id).unwrap().is_none(),
        "test precondition: Bob and Carol have no direct session"
    );

    carol.send_group_message(&group_id, "hi from carol").await.unwrap();
    let events = bob.poll_once().await.unwrap();
    assert!(
        events.iter().any(|event| matches!(
            event,
            InboxEvent::GroupMessage { text, from, .. } if text == "hi from carol" && from == &carol_id
        )),
        "the roster must authenticate a member Bob is not paired with: {events:?}"
    );
}
