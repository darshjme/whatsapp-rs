//! XEdDSA signatures over Curve25519 — the scheme WhatsApp/Signal use to sign with an X25519
//! (Montgomery) key.
//!
//! WhatsApp signs the signed pre-key and the pairing device-identity with the **identity key**,
//! which is an X25519/Curve25519 key, using libsignal's `Curve25519Sign` — i.e. XEdDSA. This module
//! implements XEdDSA sign/verify on top of `curve25519-dalek`, following the Signal specification.
//!
//! Signing maps the Montgomery private scalar onto the Edwards curve, signs Ed25519-style with a
//! domain-separated nonce, and forces the public key's sign bit to 0 (so the verifier can recover
//! the public key from the Montgomery `u`-coordinate alone). The signature is 64 bytes (`R || s`).

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Clamp a 32-byte value into a valid X25519 scalar (matches what `x25519()` does internally, so
/// the clamped scalar's public key equals the stored Montgomery public key).
fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// The XEdDSA `hash_1` domain prefix: `2^256 - 1 - 1` little-endian = `0xFE` then 31×`0xFF`.
fn hash1_prefix() -> [u8; 32] {
    let mut p = [0xFFu8; 32];
    p[0] = 0xFE;
    p
}

fn scalar_from_wide(bytes: [u8; 64]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Sign `message` with the X25519 private key, drawing a random nonce. Returns a 64-byte signature.
pub fn sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let mut nonce = [0u8; 64];
    getrandom::getrandom(&mut nonce).expect("system RNG unavailable");
    sign_with_nonce(private_key, message, &nonce)
}

/// Sign with a caller-supplied 64-byte nonce `Z` (deterministic; for tests/reproducibility).
pub fn sign_with_nonce(private_key: &[u8; 32], message: &[u8], nonce: &[u8; 64]) -> [u8; 64] {
    let scalar = Scalar::from_bytes_mod_order(clamp(*private_key));

    // E = k*B; force the public key A to have sign bit 0, adjusting the private scalar `a` to match.
    let e = ED25519_BASEPOINT_POINT * scalar;
    let sign_bit = (e.compress().as_bytes()[31] >> 7) & 1;
    let (a, big_a) = if sign_bit == 1 {
        (-scalar, -e)
    } else {
        (scalar, e)
    };
    let a_bytes = a.to_bytes();
    let big_a = big_a.compress();

    // r = hash_1(prefix || a || M || Z)
    let mut h = Sha512::new();
    h.update(hash1_prefix());
    h.update(a_bytes);
    h.update(message);
    h.update(nonce);
    let r = scalar_from_wide(h.finalize().into());
    let big_r = (ED25519_BASEPOINT_POINT * r).compress();

    // h = SHA512(R || A || M)
    let mut h = Sha512::new();
    h.update(big_r.as_bytes());
    h.update(big_a.as_bytes());
    h.update(message);
    let hs = scalar_from_wide(h.finalize().into());

    // s = r + h*a
    let s = r + hs * a;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(big_r.as_bytes());
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
}

/// Verify a 64-byte XEdDSA signature against an X25519 (Montgomery) public key.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let big_a = match MontgomeryPoint(*public_key).to_edwards(0) {
        Some(p) => p,
        None => return false,
    };
    let r_bytes: [u8; 32] = signature[..32].try_into().expect("32 bytes");
    let s_bytes: [u8; 32] = signature[32..].try_into().expect("32 bytes");
    let s = match Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) {
        Some(s) => s,
        None => return false,
    };

    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(big_a.compress().as_bytes());
    h.update(message);
    let hs = scalar_from_wide(h.finalize().into());

    // R_check = s*B - h*A  must equal R.
    let r_check = ED25519_BASEPOINT_POINT * s - big_a * hs;
    r_check.compress().to_bytes() == r_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::X25519_BASEPOINT;

    /// Derive the Montgomery public key the way the keystore does (clamped scalar * basepoint).
    fn public_of(private: &[u8; 32]) -> [u8; 32] {
        let scalar = Scalar::from_bytes_mod_order(clamp(*private));
        (X25519_BASEPOINT * scalar).to_bytes()
    }

    #[test]
    fn sign_then_verify() {
        let mut priv_key = [0u8; 32];
        getrandom::getrandom(&mut priv_key).unwrap();
        let pub_key = public_of(&priv_key);

        let msg = b"\x05signed-pre-key-public-key-goes-here!!";
        let sig = sign(&priv_key, msg);
        assert!(verify(&pub_key, msg, &sig));
    }

    #[test]
    fn tampered_message_fails() {
        let priv_key = [7u8; 32];
        let pub_key = public_of(&priv_key);
        let sig = sign(&priv_key, b"original message");
        assert!(!verify(&pub_key, b"different message", &sig));
    }

    #[test]
    fn tampered_signature_fails() {
        let priv_key = [9u8; 32];
        let pub_key = public_of(&priv_key);
        let mut sig = sign(&priv_key, b"msg");
        sig[0] ^= 0x01;
        assert!(!verify(&pub_key, b"msg", &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let sig = sign(&[1u8; 32], b"msg");
        let other_pub = public_of(&[2u8; 32]);
        assert!(!verify(&other_pub, b"msg", &sig));
    }

    #[test]
    fn deterministic_nonce_is_stable_and_valid() {
        let priv_key = [3u8; 32];
        let pub_key = public_of(&priv_key);
        let z = [42u8; 64];
        let a = sign_with_nonce(&priv_key, b"x", &z);
        let b = sign_with_nonce(&priv_key, b"x", &z);
        assert_eq!(a, b, "same nonce -> same signature");
        assert!(verify(&pub_key, b"x", &a));
    }
}
