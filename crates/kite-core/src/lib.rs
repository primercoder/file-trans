//! Platform-agnostic protocol, framing and crypto primitives for Kite.

mod device_name;
mod identity;
mod ratchet;
mod x3dh;

pub use device_name::HwInfo;
pub use identity::Identity;
pub use ratchet::{RatchetMessage, Session};
pub use x3dh::{CryptoError, InitiatorKeys, PreKeyBundle, ResponderKeys, generate_spk};

/// Version of the `kite-core` crate, sourced from its manifest.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
