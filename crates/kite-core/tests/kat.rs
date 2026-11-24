use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use kite_core::{Identity, InitiatorKeys, PreKeyBundle, ResponderKeys, Session};
use sha2::{Digest as _, Sha256};

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn repeated(value: u8) -> [u8; 32] {
    bytes(&hex::encode([value; 32]))
}

fn identities() -> (Identity, Identity, [u8; 32], [u8; 32], [u8; 32]) {
    // Fixed IK/SPK/OPK/EK scalars, written as hardcoded hex for reproducibility.
    let identity = |secret: [u8; 32]| {
        let pem = ed25519_dalek::SigningKey::from_bytes(&secret)
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();
        Identity::from_private(&pem).unwrap()
    };
    (
        identity(repeated(1)),
        identity(repeated(2)),
        repeated(3),
        repeated(4),
        repeated(5),
    )
}

#[test]
fn x3dh_3dh_and_4dh_known_answers() {
    let (alice, bob, spk_private, opk_private, ek) = identities();
    let spk =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(spk_private)).to_bytes();
    let opk =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(opk_private)).to_bytes();
    let sig = bob.sign_bytes(&spk);
    // These values pin the derivation contract against accidental cross-change breakage.
    for (opk_part, expected) in [
        (
            None,
            "08559b4339641451b62d34fa596c205f4bdcaa39a573355dfd9d27523c845a46",
        ),
        (
            Some(opk),
            "b9e1654337cf3db7b24232336eab040db8fe72ac52848c99a7496767b1529039",
        ),
    ] {
        let bundle = PreKeyBundle {
            ik_pub: bob.ed25519_public_key(),
            spk,
            spk_sig: sig,
            opk_id: opk_part.map(|_| 9),
            opk: opk_part,
        };
        let result = InitiatorKeys::run_with_ephemeral(&bundle, &alice, ek).unwrap();
        let responder = ResponderKeys::run(
            &bob,
            &spk_private,
            opk_part.as_ref().map(|_| &opk_private),
            &alice.ed25519_public_key(),
            &result.ek_pub,
        )
        .unwrap();
        assert_eq!(hex::encode(result.shared_secret), expected);
        assert_eq!(result.shared_secret, responder.shared_secret);
    }
}

#[test]
fn double_ratchet_four_message_known_answers() {
    let responder_private = repeated(11);
    let responder_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(responder_private))
            .to_bytes();
    let mut alice = Session::init_as_initiator_with_ratchet(
        repeated(7),
        b"KAT associated data".to_vec(),
        responder_public,
        repeated(12),
    )
    .unwrap();
    let mut bob = Session::init_as_responder(
        repeated(7),
        b"KAT associated data".to_vec(),
        (responder_private, responder_public),
    )
    .unwrap();
    alice.enable_deterministic_kat();
    bob.enable_deterministic_kat();
    let a1 = alice.encrypt_with_nonce(b"kat-1", b"ad", [21; 12]).unwrap();
    assert_eq!(bob.decrypt(&a1, b"ad").unwrap(), b"kat-1");
    let b1 = bob.encrypt_with_nonce(b"kat-2", b"ad", [22; 12]).unwrap();
    assert_eq!(alice.decrypt(&b1, b"ad").unwrap(), b"kat-2");
    let a2 = alice.encrypt_with_nonce(b"kat-3", b"ad", [23; 12]).unwrap();
    assert_eq!(bob.decrypt(&a2, b"ad").unwrap(), b"kat-3");
    let b2 = bob.encrypt_with_nonce(b"kat-4", b"ad", [24; 12]).unwrap();
    assert_eq!(alice.decrypt(&b2, b"ad").unwrap(), b"kat-4");
    // Pinned serialized messages pin headers, nonces and AEAD ciphertexts.
    for (message, expected) in [
        (
            &a1,
            "0197c3b10b4d6c133a78ea5dcc1cf6421d3f81ae37b1f628ce14ca6fce7730f3330000000000000000151515151515151515151515150000000000000021695143f4953a23e2b9e845b3c56af9ff8dec14e4",
        ),
        (
            &b1,
            "01db018c69a68709ba7b909b21322f86fbe2567ebacb48707aaab9d2b0b2bce27e00000000000000001616161616161616161616161500000000000000c18c6d21bebfa1f699aab548417f7d59da8327bf89",
        ),
        (
            &a2,
            "0157f1715604e16b2aabb3f9ea938515289dcbfb6da2500040beebe700831d7e37000000000100000017171717171717171717171715000000000000002aa85c4c8ad6cee6bf7283b0b484aaa16911926da0",
        ),
        (
            &b2,
            "01a282afb406ceccbc084d21c9d17aabe0fbd616a23151a1238d28d4416c512b3d0000000001000000181818181818181818181818150000000000000072a36b2cb5ed27d19e72043cf683823de78579a9bb",
        ),
    ] {
        assert_eq!(hex::encode(bincode::serialize(message).unwrap()), expected);
    }
    assert_eq!(
        hex::encode(Sha256::digest(bincode::serialize(&alice).unwrap())),
        "1de8e02b65e50fd6405653da0abcedddcdf8ba9488602b3cc444bd7129160332",
    );
}
