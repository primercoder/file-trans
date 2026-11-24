//! Platform-agnostic protocol, framing and crypto primitives for Kite.

mod device_name;
mod identity;

pub use device_name::HwInfo;
pub use identity::Identity;

/// Version of the `kite-core` crate, sourced from its manifest.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
