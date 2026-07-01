//! The device identity keystore.
//!
//! A WhatsApp companion (linked) device is defined by a small bundle of long-lived keys and ids.
//! These are generated once on first run, shown to the phone during QR pairing, and persisted so the
//! session survives restarts. This module owns generating, saving, and loading that bundle.
//!
//! Bundle contents (matching the WhatsApp multi-device store):
//! - **noise key** — the X25519 static key used as our identity in the Noise handshake.
//! - **identity key** — the Curve25519 Signal identity keypair (used for E2E and to sign prekeys).
//! - **signed pre-key** — a Curve25519 prekey plus its signature by the identity key.
//! - **registration id** — a small random id identifying this device registration.
//! - **adv secret** — a random 32-byte key the phone and server use to authenticate pairing
//!   (`ADVSignedDeviceIdentityHMAC`).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::Error;

/// A Curve25519 / X25519 keypair (raw 32-byte scalars/points).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl KeyPair {
    /// Generate a fresh keypair (X25519 base-point multiplication, same as the Noise layer).
    pub fn generate() -> Self {
        let (private, public) = wanoise::keypair();
        KeyPair { private, public }
    }
}

/// A signed pre-key: a Curve25519 prekey with an id and the identity key's signature over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPreKey {
    pub key_id: u32,
    pub key_pair: KeyPair,
    /// XEdDSA signature by the identity key over `0x05 || prekey_public` (64 bytes).
    /// Empty until [`DeviceIdentity::sign_pre_key`] is implemented (pending the exact scheme).
    pub signature: Vec<u8>,
}

/// The full device identity bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "StoredIdentity", try_from = "StoredIdentity")]
pub struct DeviceIdentity {
    pub noise_key: KeyPair,
    pub identity_key: KeyPair,
    pub signed_pre_key: SignedPreKey,
    pub registration_id: u32,
    pub adv_secret: [u8; 32],
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("system RNG unavailable");
    b
}

/// Generate a registration id in the Signal range (1..=16380).
fn generate_registration_id() -> u32 {
    let r = u32::from_be_bytes(random_bytes::<4>());
    (r % 16380) + 1
}

/// Sign a pre-key public with the identity key: XEdDSA over `0x05 || prekey_public` (64-byte sig).
fn sign_pre_key(identity: &KeyPair, pre_key_public: &[u8; 32]) -> Vec<u8> {
    let mut to_sign = Vec::with_capacity(33);
    to_sign.push(0x05);
    to_sign.extend_from_slice(pre_key_public);
    wasignal::sign(&identity.private, &to_sign).to_vec()
}

impl DeviceIdentity {
    /// Generate a brand-new device identity (all keys fresh, signed pre-key signed by the identity
    /// key via XEdDSA over `0x05 || prekey_public`).
    pub fn generate() -> Self {
        let identity_key = KeyPair::generate();
        let pre_key = KeyPair::generate();
        let signature = sign_pre_key(&identity_key, &pre_key.public);
        DeviceIdentity {
            noise_key: KeyPair::generate(),
            identity_key,
            signed_pre_key: SignedPreKey {
                key_id: 1,
                key_pair: pre_key,
                signature,
            },
            registration_id: generate_registration_id(),
            adv_secret: random_bytes::<32>(),
        }
    }

    /// Whether the signed pre-key has been signed yet.
    pub fn is_pre_key_signed(&self) -> bool {
        self.signed_pre_key.signature.len() == 64
    }

    /// Serialize to pretty JSON (keys base64-encoded). Suitable for an on-disk session file.
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(&StoredIdentity::from(self)).map_err(|e| Error::Store(e.to_string()))
    }

    /// Load from the JSON produced by [`to_json`](Self::to_json).
    pub fn from_json(s: &str) -> Result<Self, Error> {
        let stored: StoredIdentity = serde_json::from_str(s).map_err(|e| Error::Store(e.to_string()))?;
        stored.try_into()
    }
}

// --- on-disk representation (base64 strings, stable + human-inspectable) -----------------------

#[derive(Serialize, Deserialize)]
pub(crate) struct StoredIdentity {
    version: u8,
    noise_private: String,
    noise_public: String,
    identity_private: String,
    identity_public: String,
    signed_pre_key_id: u32,
    signed_pre_key_private: String,
    signed_pre_key_public: String,
    signed_pre_key_signature: String,
    registration_id: u32,
    adv_secret: String,
}

impl From<DeviceIdentity> for StoredIdentity {
    fn from(d: DeviceIdentity) -> Self {
        StoredIdentity::from(&d)
    }
}

impl From<&DeviceIdentity> for StoredIdentity {
    fn from(d: &DeviceIdentity) -> Self {
        StoredIdentity {
            version: 1,
            noise_private: B64.encode(d.noise_key.private),
            noise_public: B64.encode(d.noise_key.public),
            identity_private: B64.encode(d.identity_key.private),
            identity_public: B64.encode(d.identity_key.public),
            signed_pre_key_id: d.signed_pre_key.key_id,
            signed_pre_key_private: B64.encode(d.signed_pre_key.key_pair.private),
            signed_pre_key_public: B64.encode(d.signed_pre_key.key_pair.public),
            signed_pre_key_signature: B64.encode(&d.signed_pre_key.signature),
            registration_id: d.registration_id,
            adv_secret: B64.encode(d.adv_secret),
        }
    }
}

fn decode32(s: &str) -> Result<[u8; 32], Error> {
    let bytes = B64.decode(s).map_err(|e| Error::Store(format!("base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::Store("expected 32-byte key".into()))
}

impl TryFrom<StoredIdentity> for DeviceIdentity {
    type Error = Error;
    fn try_from(s: StoredIdentity) -> Result<Self, Error> {
        Ok(DeviceIdentity {
            noise_key: KeyPair {
                private: decode32(&s.noise_private)?,
                public: decode32(&s.noise_public)?,
            },
            identity_key: KeyPair {
                private: decode32(&s.identity_private)?,
                public: decode32(&s.identity_public)?,
            },
            signed_pre_key: SignedPreKey {
                key_id: s.signed_pre_key_id,
                key_pair: KeyPair {
                    private: decode32(&s.signed_pre_key_private)?,
                    public: decode32(&s.signed_pre_key_public)?,
                },
                signature: B64
                    .decode(&s.signed_pre_key_signature)
                    .map_err(|e| Error::Store(format!("base64: {e}")))?,
            },
            registration_id: s.registration_id,
            adv_secret: decode32(&s.adv_secret)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_is_well_formed() {
        let d = DeviceIdentity::generate();
        assert_ne!(d.noise_key.public, [0u8; 32]);
        assert_ne!(d.identity_key.public, [0u8; 32]);
        assert_ne!(d.adv_secret, [0u8; 32]);
        assert!((1..=16380).contains(&d.registration_id));
        // distinct keys
        assert_ne!(d.noise_key.private, d.identity_key.private);
        // the signed pre-key carries a valid 64-byte XEdDSA signature by the identity key
        assert!(d.is_pre_key_signed());
        let mut signed = vec![0x05u8];
        signed.extend_from_slice(&d.signed_pre_key.key_pair.public);
        let sig: [u8; 64] = d.signed_pre_key.signature.clone().try_into().unwrap();
        assert!(wasignal::verify(&d.identity_key.public, &signed, &sig));
    }

    #[test]
    fn json_round_trips() {
        let d = DeviceIdentity::generate();
        let json = d.to_json().unwrap();
        let back = DeviceIdentity::from_json(&json).unwrap();
        assert_eq!(d, back);
    }
}
