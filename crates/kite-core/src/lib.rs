//! Platform-agnostic protocol, framing and crypto primitives for Kite.

/// Version of the `kite-core` crate, sourced from its manifest.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
