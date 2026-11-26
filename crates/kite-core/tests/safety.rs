//! Safety-number derivation: a human-verifiable fingerprint of two identities.

#[test]
fn safety_number_is_symmetric_sixty_digits_and_key_dependent() {
    let alice = [7_u8; 32];
    let bob = [9_u8; 32];

    let forward = kite_core::safety_number(&alice, &bob);
    let reverse = kite_core::safety_number(&bob, &alice);
    assert_eq!(forward, reverse, "both sides must display the same code");
    assert_eq!(forward.len(), 60);
    assert!(forward.chars().all(|c| c.is_ascii_digit()));

    let other = kite_core::safety_number(&alice, &[10_u8; 32]);
    assert_ne!(forward, other, "a different peer key must change the code");
}

#[test]
fn safety_number_matches_pinned_vector() {
    // Pinned regression vector: changing the derivation must be deliberate.
    assert_eq!(
        kite_core::safety_number(&[1_u8; 32], &[2_u8; 32]),
        "622774021528349339419470174438705083653703218722112760580457"
    );
}
