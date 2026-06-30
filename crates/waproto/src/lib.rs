//! # waproto — WhatsApp protobuf wire types
//!
//! Typed encode/decode for the WhatsApp protobuf messages, starting with the Noise
//! [`handshake`] family ([`ClientHello`](handshake::ClientHello),
//! [`ServerHello`](handshake::ServerHello), [`ClientFinish`](handshake::ClientFinish)).
//!
//! The [`pb`] module exposes the small protobuf primitive layer these types are built on; as the
//! project grows, message types (`ClientPayload`, `Message`, `WebMessageInfo`, …) are added here and
//! may later be swapped for generated `prost` types behind the same API.

#![forbid(unsafe_code)]

pub mod client_payload;
pub mod handshake;
pub mod pb;

pub use client_payload::RegistrationPayload;
pub use handshake::{ClientFinish, ClientHello, HandshakeMessage, ServerHello};

/// Errors from protobuf decoding.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Hit the end of the buffer mid-field.
    #[error("unexpected end of protobuf buffer")]
    Eof,
    /// A structurally invalid or unexpected message.
    #[error("malformed protobuf: {0}")]
    Malformed(&'static str),
    /// A protobuf wire type this minimal decoder does not handle.
    #[error("unsupported protobuf wire type {0}")]
    UnsupportedWireType(u64),
}
