use crate::Identity;

/// Host information available for constructing a default device name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HwInfo {
    /// The host's configured name.
    pub hostname: String,
    /// The host's operating system name.
    pub os: String,
    /// An optional stable hash of a machine identifier for future callers.
    pub machine_id_hash: Option<String>,
}

impl Identity {
    /// Builds `{hostname}-{os}-{suffix}` using four hex characters from the public key.
    pub fn default_device_name(&self, hw: &HwInfo) -> String {
        let verifying_key = self.verifying_key();
        let public_key = verifying_key.as_bytes();
        format!(
            "{}-{}-{}",
            hw.hostname,
            hw.os,
            hex::encode(&public_key[..2])
        )
    }
}
