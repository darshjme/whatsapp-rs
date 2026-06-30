//! # waclient — WhatsApp multi-device client
//!
//! Ties the lower layers together into a usable client: the device identity keystore
//! ([`device`]), QR companion [`pairing`], and (forthcoming) the session that drives the Noise
//! handshake, sends the registration `ClientPayload`, and exchanges [`wabin`](https://docs.rs/wabin)
//! stanzas over the encrypted [`wanoise`](https://docs.rs/wanoise) transport.
//!
//! ## Status
//! - [`device::DeviceIdentity`] — generate / persist the device key bundle. ✅
//! - [`pairing`] — build the QR payload from a server `ref` + the device keys. ✅
//! - registration `ClientPayload` (msg3) + the live `pair-device` → QR → `pair-success` flow. 🔜
//!   (pending the exact protobuf field numbers + ADV signing scheme).

#![forbid(unsafe_code)]

pub mod device;
pub mod pairing;

pub use device::{DeviceIdentity, KeyPair, SignedPreKey};
pub use pairing::{qr_payload, RefQueue};

/// Errors from the client layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failure serializing or deserializing the device keystore.
    #[error("keystore error: {0}")]
    Store(String),
    /// An error bubbled up from the transport/crypto layer.
    #[error(transparent)]
    Transport(#[from] wanoise::Error),
    /// An error bubbled up from the stanza codec.
    #[error(transparent)]
    Codec(#[from] wabin::Error),
    /// An error bubbled up from the protobuf layer.
    #[error(transparent)]
    Proto(#[from] waproto::Error),
}
