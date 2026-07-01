//! # wasignal — Signal-protocol crypto for WhatsApp
//!
//! WhatsApp's end-to-end encryption and device pairing are built on the Signal protocol. This crate
//! provides the Signal cryptographic primitives `waclient` needs, starting with Curve25519
//! [`xeddsa`] signatures (used to sign the signed pre-key and the pairing device identity).
//!
//! Future: identity/session state, sender keys, the double ratchet.

#![forbid(unsafe_code)]

pub mod pcrypto;
pub mod ratchet;
pub mod xeddsa;

pub use pcrypto::{aes256_ctr, aes256_gcm_open, aes256_gcm_seal, hkdf_sha256, pbkdf2_sha256};
pub use ratchet::{dh, ChainKey, MessageKeys, RootKey};
pub use xeddsa::{sign, verify};

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC-SHA256 of `data` under `key` (used to verify the `ADVSignedDeviceIdentityHMAC` during
/// pairing). Returns the 32-byte tag.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod hmac_tests {
    use super::*;

    #[test]
    fn hmac_is_deterministic_and_key_sensitive() {
        let a = hmac_sha256(b"secret-key", b"message");
        assert_eq!(a, hmac_sha256(b"secret-key", b"message"));
        assert_ne!(a, hmac_sha256(b"other-key", b"message"));
        assert_eq!(a.len(), 32);
    }
}
