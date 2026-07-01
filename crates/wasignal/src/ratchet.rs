//! Double-ratchet crypto primitives (Signal spec, as used by WhatsApp/libsignal): the chain-key and
//! root-key KDFs, message-key derivation, and the AES-256-CBC + HMAC message cipher.
//!
//! This is the crypto *foundation*; the ratchet state machine (DH ratchet, skipped keys), X3DH, and
//! message serialization build on top of it.

use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;

use crate::{hkdf_sha256, hmac_sha256};

/// X25519 Diffie–Hellman (clamps the scalar, matching libsignal / the rest of the stack).
pub fn dh(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let mut k = *secret;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(k);
    (scalar * MontgomeryPoint(*public)).to_bytes()
}

/// A chain key — advances one step per message, yielding a message key each step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainKey {
    pub key: [u8; 32],
    pub index: u32,
}

impl ChainKey {
    pub fn new(key: [u8; 32], index: u32) -> Self {
        ChainKey { key, index }
    }

    /// The message keys for the current index (`HKDF(HMAC(ck,0x01), "WhisperMessageKeys")`).
    pub fn message_keys(&self) -> MessageKeys {
        let seed = hmac_sha256(&self.key, &[0x01]);
        let okm = hkdf_sha256(&seed, &[], b"WhisperMessageKeys", 80);
        MessageKeys {
            cipher_key: okm[0..32].try_into().unwrap(),
            mac_key: okm[32..64].try_into().unwrap(),
            iv: okm[64..80].try_into().unwrap(),
            counter: self.index,
        }
    }

    /// The next chain key (`HMAC(ck, 0x02)`).
    pub fn next(&self) -> ChainKey {
        ChainKey {
            key: hmac_sha256(&self.key, &[0x02]),
            index: self.index + 1,
        }
    }
}

/// The per-message keys derived from a chain key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageKeys {
    pub cipher_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub iv: [u8; 16],
    pub counter: u32,
}

/// A root key — evolves on each DH ratchet step, producing a fresh chain key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootKey {
    pub key: [u8; 32],
}

impl RootKey {
    pub fn new(key: [u8; 32]) -> Self {
        RootKey { key }
    }

    /// DH ratchet step: `HKDF(dh_output, salt=rootKey, "WhisperRatchet")` → `(newRootKey, chainKey)`.
    pub fn create_chain(&self, dh_output: &[u8; 32]) -> (RootKey, ChainKey) {
        let okm = hkdf_sha256(dh_output, &self.key, b"WhisperRatchet", 64);
        (
            RootKey { key: okm[0..32].try_into().unwrap() },
            ChainKey { key: okm[32..64].try_into().unwrap(), index: 0 },
        )
    }
}

/// AES-256-CBC encrypt with PKCS7 padding (the Signal message cipher).
pub fn encrypt_cbc(cipher_key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    cbc::Encryptor::<Aes256>::new(cipher_key.into(), iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

/// AES-256-CBC decrypt with PKCS7 padding.
pub fn decrypt_cbc(cipher_key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Option<Vec<u8>> {
    cbc::Decryptor::<Aes256>::new(cipher_key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_is_symmetric() {
        let base = {
            let mut b = [0u8; 32];
            b[0] = 9; // X25519 base point u = 9
            b
        };
        let a = [11u8; 32];
        let a_pub = dh(&a, &base);
        let b = [22u8; 32];
        let b_pub = dh(&b, &base);
        assert_eq!(dh(&a, &b_pub), dh(&b, &a_pub));
    }

    #[test]
    fn chain_key_advances_and_message_keys_differ() {
        let ck0 = ChainKey::new([7u8; 32], 0);
        let mk0 = ck0.message_keys();
        assert_eq!(mk0.counter, 0);
        let ck1 = ck0.next();
        assert_eq!(ck1.index, 1);
        assert_ne!(ck0.key, ck1.key);
        assert_ne!(ck0.message_keys().cipher_key, ck1.message_keys().cipher_key);
        // deterministic
        assert_eq!(ck0.message_keys(), mk0);
    }

    #[test]
    fn two_chains_from_same_root_stay_in_lockstep() {
        // Sender and receiver derive the same chain from the same root + dh output.
        let root = RootKey::new([1u8; 32]);
        let dh_out = [2u8; 32];
        let (r_a, mut ck_a) = root.create_chain(&dh_out);
        let (r_b, mut ck_b) = root.create_chain(&dh_out);
        assert_eq!(r_a, r_b);
        for _ in 0..5 {
            assert_eq!(ck_a.message_keys(), ck_b.message_keys());
            ck_a = ck_a.next();
            ck_b = ck_b.next();
        }
    }

    #[test]
    fn aes_cbc_round_trips() {
        let key = [9u8; 32];
        let iv = [3u8; 16];
        let msg = b"the plaintext WhatsApp Message protobuf, padded";
        let ct = encrypt_cbc(&key, &iv, msg);
        assert_ne!(ct, msg);
        assert_eq!(decrypt_cbc(&key, &iv, &ct).unwrap(), msg);
    }

    #[test]
    fn message_key_encrypts_a_message() {
        let ck = ChainKey::new([5u8; 32], 0);
        let mk = ck.message_keys();
        let pt = b"hello";
        let ct = encrypt_cbc(&mk.cipher_key, &mk.iv, pt);
        assert_eq!(decrypt_cbc(&mk.cipher_key, &mk.iv, &ct).unwrap(), pt);
    }
}
