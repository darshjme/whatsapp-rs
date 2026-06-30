//! # wanoise — WhatsApp transport layer
//!
//! Everything needed to take a raw byte stream to/from `g.whatsapp.net` and turn it into an
//! authenticated, encrypted channel that carries [`wabin`](https://docs.rs/wabin) stanzas:
//!
//! - [`frame`] — the 3-byte length framing and stream reassembly, plus the connection header.
//! - [`handshake`] — the `Noise_XX_25519_AESGCM_SHA256` handshake and the post-handshake
//!   [`Transport`](handshake::Transport) cipher.
//!
//! This crate is deliberately **transport-agnostic** (bytes in, bytes out). The actual socket
//! (TCP or WebSocket) and the `ClientPayload` protobuf are supplied by `waclient`.
//!
//! ## Typical flow (client)
//! ```no_run
//! use wanoise::frame::{wa_conn_header, encode_frame, FrameReader};
//! use wanoise::handshake::{Handshake, generate_keypair};
//!
//! // Persist this across logins — it's the device identity.
//! let identity = generate_keypair()?;
//! let prologue = wa_conn_header();
//!
//! let mut hs = Handshake::new_initiator(&identity.private, &prologue)?;
//! // 1. send the connection header, then framed handshake message 1
//! let mut outbound = prologue.to_vec();
//! encode_frame(&hs.write_message(&[])?, &mut outbound)?;
//! // ... write `outbound` to the socket, read the server's reply into `FrameReader` ...
//! # Ok::<(), wanoise::Error>(())
//! ```

#![forbid(unsafe_code)]

pub mod frame;
pub mod handshake;

pub use handshake::{generate_keypair, Handshake, Keypair, Transport};

/// Errors from the transport layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A frame exceeded the 3-byte (16 MiB) length limit.
    #[error("frame too large: {0} bytes (max {max})", max = crate::frame::MAX_FRAME_LEN)]
    FrameTooLarge(usize),
    /// The hard-coded Noise parameter string failed to parse (should be unreachable).
    #[error("invalid noise parameters")]
    BadParams,
    /// An error from the underlying Noise implementation (handshake/crypto failure).
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),
}
