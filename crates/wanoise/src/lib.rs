//! # wanoise — WhatsApp transport layer
//!
//! Everything needed to take a raw byte stream to/from `g.whatsapp.net` and turn it into an
//! authenticated, encrypted channel that carries [`wabin`](https://docs.rs/wabin) stanzas:
//!
//! - [`frame`] — the 3-byte length framing and stream reassembly, plus the connection header.
//! - [`noise`] — a hand-rolled `Noise_XX_25519_AESGCM_SHA256` handshake (byte-faithful to
//!   WhatsApp's implementation) and the post-handshake [`NoiseTransport`](noise::NoiseTransport).
//!
//! This crate is deliberately **transport-agnostic** (bytes in, bytes out). The actual socket
//! (TCP or WebSocket), the protobuf `HandshakeMessage` envelopes, and the `ClientPayload` are
//! supplied by `waclient`.
//!
//! ## Client handshake sketch
//! ```no_run
//! use wanoise::frame::{wa_conn_header, encode_frame};
//! use wanoise::noise::XxInitiator;
//!
//! let prologue = wa_conn_header();          // WA 06 03
//! let mut hs = XxInitiator::new(&prologue);
//! let client_hello_ephemeral = hs.ephemeral();   // -> put in a ClientHello protobuf, framed & sent
//! // ... receive ServerHello fields from the wire ...
//! // let (server_static, cert) = hs.read_server_hello(&server_eph, &enc_static, &enc_payload)?;
//! let mut first = prologue.to_vec();
//! encode_frame(&[], &mut first)?;
//! # Ok::<(), wanoise::Error>(())
//! ```

#![forbid(unsafe_code)]

pub mod frame;
pub mod noise;

pub use noise::{dh, keypair, NoiseState, NoiseTransport, XxInitiator};

/// Errors from the transport layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A frame exceeded the 3-byte (16 MiB) length limit.
    #[error("frame too large: {0} bytes (max {max})", max = crate::frame::MAX_FRAME_LEN)]
    FrameTooLarge(usize),
    /// An AEAD operation was attempted before the first key was derived.
    #[error("noise cipher not initialized yet")]
    NoiseUninitialized,
    /// An AEAD encrypt/decrypt (tag verification) failed.
    #[error("crypto error: {0}")]
    Crypto(&'static str),
    /// A key or field had an unexpected length.
    #[error("bad length: {0}")]
    BadLength(&'static str),
}
