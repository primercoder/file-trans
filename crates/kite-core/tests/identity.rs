use kite_core::{HwInfo, Identity};

const PRIVATE_KEY_A: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f
-----END PRIVATE KEY-----
";
const PRIVATE_KEY_B: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g
-----END PRIVATE KEY-----
";

fn hw_info() -> HwInfo {
    HwInfo {
        hostname: "office".to_owned(),
        os: "Linux".to_owned(),
        machine_id_hash: None,
    }
}

#[test]
fn device_id_is_stable_and_unique() {
    let identity = Identity::generate();
    let other = Identity::generate();

    assert_eq!(identity.device_id(), identity.device_id());
    assert_ne!(identity.device_id(), other.device_id());
}

#[test]
fn device_id_is_32_character_lowercase_hex() {
    let identity = Identity::generate();
    let device_id = identity.device_id();

    assert_eq!(device_id.len(), 32);
    assert!(
        device_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

#[test]
fn private_pem_roundtrip_preserves_device_id() {
    let identity = Identity::generate();
    let restored = Identity::from_private(&identity.private_pem()).unwrap();

    assert_eq!(identity.device_id(), restored.device_id());
}

#[test]
fn default_device_name_uses_identity_suffix() {
    let identity = Identity::from_private(PRIVATE_KEY_A).unwrap();
    let other = Identity::from_private(PRIVATE_KEY_B).unwrap();

    assert_ne!(
        identity.default_device_name(&hw_info()),
        other.default_device_name(&hw_info())
    );
}

#[test]
fn default_device_name_has_exact_format() {
    let identity = Identity::from_private(PRIVATE_KEY_A).unwrap();

    assert_eq!(
        identity.default_device_name(&hw_info()),
        "office-Linux-03a107bf"
    );
}

#[test]
fn default_device_name_is_stable() {
    let identity = Identity::generate();
    let hw = hw_info();

    assert_eq!(
        identity.default_device_name(&hw),
        identity.default_device_name(&hw)
    );
}
