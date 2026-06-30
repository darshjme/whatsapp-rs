//! # wasignal — Signal-protocol crypto for WhatsApp
//!
//! WhatsApp's end-to-end encryption and device pairing are built on the Signal protocol. This crate
//! provides the Signal cryptographic primitives `waclient` needs, starting with Curve25519
//! [`xeddsa`] signatures (used to sign the signed pre-key and the pairing device identity).
//!
//! Future: identity/session state, sender keys, the double ratchet.

#![forbid(unsafe_code)]

pub mod xeddsa;

pub use xeddsa::{sign, verify};
