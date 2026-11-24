use kite_core::{RatchetMessage, Session};

fn sessions() -> (Session, Session) {
    let sk = [7_u8; 32];
    let ad = b"alice identity || bob identity".to_vec();
    let responder_private = [11_u8; 32];
    let responder_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(responder_private))
            .to_bytes();
    let alice = Session::init_as_initiator(sk, ad.clone(), responder_public).unwrap();
    let bob = Session::init_as_responder(sk, ad, (responder_private, responder_public)).unwrap();
    (alice, bob)
}

fn external_ad(round: usize) -> Vec<u8> {
    format!("kite-envelope-{round}").into_bytes()
}

#[test]
fn roundtrip_reply_and_five_alternating_rounds() {
    let (mut alice, mut bob) = sessions();
    for round in 0..5 {
        let ad = external_ad(round);
        let message = alice.encrypt(b"from alice", &ad).unwrap();
        assert_eq!(bob.decrypt(&message, &ad).unwrap(), b"from alice");

        let reply = bob.encrypt(b"from bob", &ad).unwrap();
        assert_eq!(alice.decrypt(&reply, &ad).unwrap(), b"from bob");
    }
}

#[test]
fn repeated_plaintext_has_different_ciphertext_and_message_keys() {
    let (mut alice, mut bob) = sessions();
    let first = alice.encrypt(b"same plaintext", b"ad").unwrap();
    let second = alice.encrypt(b"same plaintext", b"ad").unwrap();
    assert_ne!(first.ciphertext, second.ciphertext);
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.header_seq, second.header_seq);
    assert_eq!(bob.decrypt(&second, b"ad").unwrap(), b"same plaintext");
    assert_eq!(bob.decrypt(&first, b"ad").unwrap(), b"same plaintext");
}

#[test]
fn out_of_order_messages_within_one_chain_decrypt() {
    let (mut alice, mut bob) = sessions();
    let msg1 = alice.encrypt(b"one", b"ad").unwrap();
    let msg2 = alice.encrypt(b"two", b"ad").unwrap();
    let msg3 = alice.encrypt(b"three", b"ad").unwrap();

    assert_eq!(bob.decrypt(&msg3, b"ad").unwrap(), b"three");
    assert_eq!(bob.decrypt(&msg1, b"ad").unwrap(), b"one");
    assert_eq!(bob.decrypt(&msg2, b"ad").unwrap(), b"two");
}

#[test]
fn tampering_is_detected() {
    let (mut alice, mut bob) = sessions();
    let original = alice.encrypt(b"authenticated", b"ad").unwrap();

    let mut bad_ciphertext = clone_message(&original);
    bad_ciphertext.ciphertext[0] ^= 1;
    assert!(bob.decrypt(&bad_ciphertext, b"ad").is_err());

    let mut bad_nonce = clone_message(&original);
    bad_nonce.nonce[0] ^= 1;
    assert!(bob.decrypt(&bad_nonce, b"ad").is_err());

    assert!(bob.decrypt(&original, b"wrong ad").is_err());
}

#[test]
fn failed_cached_decrypt_does_not_consume_message_key() {
    let (mut alice, mut bob) = sessions();
    let first = alice.encrypt(b"one", b"ad").unwrap();
    let second = alice.encrypt(b"two", b"ad").unwrap();
    assert_eq!(bob.decrypt(&second, b"ad").unwrap(), b"two");

    let mut tampered = clone_message(&first);
    tampered.ciphertext[0] ^= 1;
    assert!(bob.decrypt(&tampered, b"ad").is_err());
    assert_eq!(bob.decrypt(&first, b"ad").unwrap(), b"one");
}

#[test]
fn skipped_message_key_cache_is_capped() {
    let (mut alice, mut bob) = sessions();
    let messages: Vec<_> = (0..66)
        .map(|i| {
            alice
                .encrypt(format!("message {i}").as_bytes(), b"ad")
                .unwrap()
        })
        .collect();
    assert!(bob.decrypt(&messages[65], b"ad").is_err());
}

fn clone_message(message: &RatchetMessage) -> RatchetMessage {
    RatchetMessage {
        ratchet_pub: message.ratchet_pub,
        header_seq: message.header_seq,
        prev_chain_len: message.prev_chain_len,
        nonce: message.nonce,
        ciphertext: message.ciphertext.clone(),
    }
}
