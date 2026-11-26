//! Human-verifiable safety numbers.
//!
//! A safety number is a 60-digit fingerprint of two Ed25519 identity keys. Both
//! sides derive the same value from the keys they already hold, so users can
//! compare it out of band (in person, over a separate channel) and thereby
//! confirm that no directory or server replaced either identity. The derivation
//! is symmetric and independent of which side initiated the pairing.

use hkdf::Hkdf;
use sha2::Sha256;

const INFO: &[u8] = b"kite-safety-number-v1";
const GROUPS: usize = 12;
const DIGITS_PER_GROUP: usize = 5;

/// Derives the 60-digit safety number for two raw Ed25519 public keys.
///
/// The keys are sorted before hashing, so `safety_number(a, b)` equals
/// `safety_number(b, a)`. The result is a decimal string without separators;
/// the UI is responsible for grouping it for display.
pub fn safety_number(first: &[u8; 32], second: &[u8; 32]) -> String {
    let (low, high) = if first <= second {
        (first, second)
    } else {
        (second, first)
    };
    let mut input = [0_u8; 64];
    input[..32].copy_from_slice(low);
    input[32..].copy_from_slice(high);

    let mut digest = [0_u8; GROUPS * 4];
    Hkdf::<Sha256>::new(None, &input)
        .expand(INFO, &mut digest)
        .expect("48 bytes is a valid HKDF-SHA256 output length");

    let mut code = String::with_capacity(GROUPS * DIGITS_PER_GROUP);
    for chunk in digest.as_chunks::<4>().0 {
        let value = u32::from_be_bytes(*chunk) % 100_000;
        code.push_str(&format!("{value:05}"));
    }
    code
}
