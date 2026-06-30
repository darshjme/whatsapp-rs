//! Symmetric crypto primitives used by the phone-number (pairing-code) link flow:
//! PBKDF2-HMAC-SHA256, AES-256-CTR, AES-256-GCM, and HKDF-SHA256. These match the algorithms in
//! whatsmeow's `pair-code.go`.

use aes::Aes256;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use sha2::Sha256;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// PBKDF2-HMAC-SHA256.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    out
}

/// AES-256-CTR keystream XOR (Go `cipher.NewCTR`: 128-bit big-endian counter from the IV).
/// Encryption and decryption are the same operation.
pub fn aes256_ctr(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    cipher.apply_keystream(&mut buf);
    buf
}

/// AES-256-GCM seal (no associated data). Returns `ciphertext || tag`.
pub fn aes256_gcm_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: &[] })
        .expect("aes-gcm seal")
}

/// AES-256-GCM open (no associated data). `None` if the tag fails.
pub fn aes256_gcm_open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: &[] })
        .ok()
}

/// HKDF-SHA256 (extract + expand). Empty `salt` is treated as absent (whatsmeow passes `nil`).
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out).expect("hkdf expand");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_ctr_round_trips() {
        let key = [7u8; 32];
        let iv = [3u8; 16];
        let msg = b"the quick brown fox jumps over the lazy companion key";
        let ct = aes256_ctr(&key, &iv, msg);
        assert_ne!(ct, msg);
        assert_eq!(aes256_ctr(&key, &iv, &ct), msg); // CTR is its own inverse
    }

    #[test]
    fn aes_gcm_round_trips_and_detects_tamper() {
        let key = [9u8; 32];
        let nonce = [1u8; 12];
        let pt = b"identity || primary || advRandom";
        let mut ct = aes256_gcm_seal(&key, &nonce, pt);
        assert_eq!(aes256_gcm_open(&key, &nonce, &ct).unwrap(), pt);
        ct[0] ^= 1;
        assert!(aes256_gcm_open(&key, &nonce, &ct).is_none());
    }

    #[test]
    fn pbkdf2_and_hkdf_are_deterministic() {
        let a = pbkdf2_sha256(b"ABCD2345", b"salt-salt", 1000, 32);
        assert_eq!(a, pbkdf2_sha256(b"ABCD2345", b"salt-salt", 1000, 32));
        assert_eq!(a.len(), 32);
        let h = hkdf_sha256(b"shared-secret", b"", b"adv_secret", 32);
        assert_eq!(h, hkdf_sha256(b"shared-secret", b"", b"adv_secret", 32));
        assert_eq!(h.len(), 32);
        assert_ne!(h, hkdf_sha256(b"shared-secret", b"", b"other_info", 32));
    }
}
