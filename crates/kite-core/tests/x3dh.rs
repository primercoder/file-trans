use kite_core::{CryptoError, Identity, InitiatorKeys, PreKeyBundle, ResponderKeys, generate_spk};

#[test]
fn four_dh_derives_matching_shared_secrets() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let (spk_priv, spk, spk_sig) = generate_spk(&bob);
    let opk_priv = [42_u8; 32];
    let opk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(opk_priv));
    let bundle = PreKeyBundle {
        ik_pub: bob.ed25519_public_key(),
        spk,
        spk_sig,
        opk_id: Some(7),
        opk: Some(opk.to_bytes()),
    };

    let initiator = InitiatorKeys::run(&bundle, &alice).unwrap();
    let responder = ResponderKeys::run(
        &bob,
        &spk_priv,
        Some(&opk_priv),
        &alice.ed25519_public_key(),
        &initiator.ek_pub,
    )
    .unwrap();

    assert_eq!(initiator.shared_secret, responder.shared_secret);
    assert_eq!(initiator.used_opk_id, Some(7));
}

#[test]
fn three_dh_derives_matching_shared_secrets() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let (spk_priv, spk, spk_sig) = generate_spk(&bob);
    let bundle = PreKeyBundle {
        ik_pub: bob.ed25519_public_key(),
        spk,
        spk_sig,
        opk_id: None,
        opk: None,
    };

    let initiator = InitiatorKeys::run(&bundle, &alice).unwrap();
    let responder = ResponderKeys::run(
        &bob,
        &spk_priv,
        None,
        &alice.ed25519_public_key(),
        &initiator.ek_pub,
    )
    .unwrap();

    assert_eq!(initiator.shared_secret, responder.shared_secret);
    assert_eq!(initiator.used_opk_id, None);
}

#[test]
fn invalid_spk_signature_is_rejected() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let (_, spk, mut spk_sig) = generate_spk(&bob);
    spk_sig[0] ^= 1;
    let bundle = PreKeyBundle {
        ik_pub: bob.ed25519_public_key(),
        spk,
        spk_sig,
        opk_id: None,
        opk: None,
    };

    assert!(matches!(
        InitiatorKeys::run(&bundle, &alice),
        Err(CryptoError::BadSignature)
    ));
}

#[test]
fn low_order_spk_produces_zero_dh_error() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let (_, _, _) = generate_spk(&bob);
    let spk = [0_u8; 32];
    let spk_sig = bob.sign_bytes(&spk);
    let bundle = PreKeyBundle {
        ik_pub: bob.ed25519_public_key(),
        spk,
        spk_sig,
        opk_id: None,
        opk: None,
    };

    assert!(matches!(
        InitiatorKeys::run(&bundle, &alice),
        Err(CryptoError::ZeroDh)
    ));
}
