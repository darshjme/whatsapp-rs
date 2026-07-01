//! QR companion pairing.
//!
//! After the Noise handshake completes with a *registration* `ClientPayload`, the server sends a
//! `pair-device` IQ containing one or more short-lived **ref** strings. The client builds a QR
//! payload from a ref plus its public keys; the user scans it with the WhatsApp phone app, which
//! authorizes the link. The QR string format (matching whatsmeow `pair-code.go`) is:
//!
//! ```text
//! <ref>,<base64(noise_public)>,<base64(identity_public)>,<base64(adv_secret)>
//! ```
//!
//! all joined by commas, with standard base64. The refs rotate (~every 20s); the client re-renders
//! the QR with the next ref until the phone scans one.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use waproto::adv::{
    AdvDeviceIdentity, AdvSignedDeviceIdentity, AdvSignedDeviceIdentityHmac, ENC_TYPE_HOSTED,
};

use crate::device::DeviceIdentity;
use crate::Error;

/// Account-signature prefix `[6, 0]` (`[6, 5]` for hosted accounts).
const ADV_ACCOUNT_PREFIX: [u8; 2] = [6, 0];
const ADV_ACCOUNT_PREFIX_HOSTED: [u8; 2] = [6, 5];
/// Device-signature prefix `[6, 1]`.
const ADV_DEVICE_PREFIX: [u8; 2] = [6, 1];

/// The result of processing a `pair-success`: the self-signed identity to return in
/// `<pair-device-sign>` and the `key-index` attribute for that stanza.
#[derive(Clone, Debug)]
pub struct PairSuccess {
    pub self_signed_identity: Vec<u8>,
    pub key_index: u32,
    /// The account (phone) identity public key — kept for the session before it is nulled out of the
    /// self-signed identity sent back to the server.
    pub account_signature_key: Vec<u8>,
}

/// Process the `<device-identity>` blob from a `pair-success` IQ.
///
/// Steps (matching whatsmeow `pair.go`):
/// 1. verify the HMAC over `details` (prefixed `[6,5]` only for hosted accounts) with the adv secret,
/// 2. verify the account signature over `[6,0] || details || identityPub`,
/// 3. produce our device signature over `[6,1] || details || identityPub || accountSignatureKey`,
/// 4. null the account signature key and re-encode the self-signed identity.
pub fn complete_pair_success(
    device_identity_bytes: &[u8],
    device: &DeviceIdentity,
) -> Result<PairSuccess, Error> {
    let container = AdvSignedDeviceIdentityHmac::decode(device_identity_bytes)?;

    // 1. HMAC verification.
    let mut mac_input = Vec::new();
    if container.account_type == ENC_TYPE_HOSTED {
        mac_input.extend_from_slice(&ADV_ACCOUNT_PREFIX_HOSTED);
    }
    mac_input.extend_from_slice(&container.details);
    let expected = wasignal::hmac_sha256(&device.adv_secret, &mac_input);
    if expected.as_slice() != container.hmac.as_slice() {
        return Err(Error::Pairing("device-identity HMAC mismatch"));
    }

    let mut signed = AdvSignedDeviceIdentity::decode(&container.details)?;
    let inner = AdvDeviceIdentity::decode(&signed.details)?;
    let identity_pub = device.identity_key.public;

    // 2. Verify the account (phone) signature.
    let account_prefix = if inner.device_type == ENC_TYPE_HOSTED {
        ADV_ACCOUNT_PREFIX_HOSTED
    } else {
        ADV_ACCOUNT_PREFIX
    };
    let account_msg = concat(&[&account_prefix, &signed.details, &identity_pub]);
    let account_key: [u8; 32] = signed
        .account_signature_key
        .as_slice()
        .try_into()
        .map_err(|_| Error::Pairing("bad accountSignatureKey length"))?;
    let account_sig: [u8; 64] = signed
        .account_signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::Pairing("bad accountSignature length"))?;
    if !wasignal::verify(&account_key, &account_msg, &account_sig) {
        return Err(Error::Pairing("account signature verification failed"));
    }

    // 3. Produce our device signature.
    let device_msg = concat(&[
        &ADV_DEVICE_PREFIX,
        &signed.details,
        &identity_pub,
        &signed.account_signature_key,
    ]);
    signed.device_signature = wasignal::sign(&device.identity_key.private, &device_msg).to_vec();

    // Keep the account key for the session, then null it out of the self-signed identity.
    let account_signature_key = signed.account_signature_key.clone();
    signed.account_signature_key.clear();
    Ok(PairSuccess {
        self_signed_identity: signed.encode(),
        key_index: inner.key_index,
        account_signature_key,
    })
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// Build the QR payload string for one server-provided `ref`.
pub fn qr_payload(reference: &str, device: &DeviceIdentity) -> String {
    [
        reference.to_string(),
        B64.encode(device.noise_key.public),
        B64.encode(device.identity_key.public),
        B64.encode(device.adv_secret),
    ]
    .join(",")
}

/// The set of refs from a `pair-device` IQ, consumed one at a time as each expires.
#[derive(Debug, Default)]
pub struct RefQueue {
    refs: std::collections::VecDeque<String>,
}

impl RefQueue {
    /// Build from the `ref` values found in a `pair-device` IQ (in order).
    pub fn new(refs: impl IntoIterator<Item = String>) -> Self {
        RefQueue {
            refs: refs.into_iter().collect(),
        }
    }

    /// Take the next ref to display, if any remain.
    pub fn next_ref(&mut self) -> Option<String> {
        self.refs.pop_front()
    }

    /// Refs still available.
    pub fn remaining(&self) -> usize {
        self.refs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_payload_has_four_comma_fields_in_order() {
        let d = DeviceIdentity::generate();
        let s = qr_payload("REF123", &d);
        let parts: Vec<&str> = s.split(',').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "REF123");
        assert_eq!(parts[1], B64.encode(d.noise_key.public));
        assert_eq!(parts[2], B64.encode(d.identity_key.public));
        assert_eq!(parts[3], B64.encode(d.adv_secret));
        // base64 of 32 bytes is 44 chars (with padding)
        assert_eq!(parts[1].len(), 44);
    }

    #[test]
    fn ref_queue_drains_in_order() {
        let mut q = RefQueue::new(["a".into(), "b".into(), "c".into()]);
        assert_eq!(q.remaining(), 3);
        assert_eq!(q.next_ref().as_deref(), Some("a"));
        assert_eq!(q.next_ref().as_deref(), Some("b"));
        assert_eq!(q.next_ref().as_deref(), Some("c"));
        assert_eq!(q.next_ref(), None);
    }

    /// Build a valid `pair-success` device-identity the way the phone/server would, run our
    /// handler, and verify the device signature it produces is correct. Proves the full
    /// HMAC-verify -> account-sig-verify -> device-sign -> re-encode pipeline.
    fn build_server_device_identity(device: &DeviceIdentity) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        // Phone "account" identity.
        let (account_priv, account_pub) = wanoise::keypair();
        let inner = AdvDeviceIdentity {
            raw_id: 42,
            timestamp: 1_700_000_000,
            key_index: 3,
            account_type: 0,
            device_type: 0,
        };
        let inner_bytes = inner.encode();
        // Account signs [6,0] || inner || ourIdentityPub.
        let mut account_msg = vec![6u8, 0];
        account_msg.extend_from_slice(&inner_bytes);
        account_msg.extend_from_slice(&device.identity_key.public);
        let account_sig = wasignal::sign(&account_priv, &account_msg);
        let signed = AdvSignedDeviceIdentity {
            details: inner_bytes.clone(),
            account_signature_key: account_pub.to_vec(),
            account_signature: account_sig.to_vec(),
            device_signature: Vec::new(),
        };
        let signed_bytes = signed.encode();
        let hmac = wasignal::hmac_sha256(&device.adv_secret, &signed_bytes);
        let container = AdvSignedDeviceIdentityHmac {
            details: signed_bytes,
            hmac: hmac.to_vec(),
            account_type: 0,
        };
        (container.encode(), account_pub, inner_bytes)
    }

    #[test]
    fn pair_success_full_pipeline() {
        let device = DeviceIdentity::generate();
        let (container_bytes, account_pub, inner_bytes) = build_server_device_identity(&device);

        let result = complete_pair_success(&container_bytes, &device).unwrap();
        assert_eq!(result.key_index, 3);

        let out = AdvSignedDeviceIdentity::decode(&result.self_signed_identity).unwrap();
        assert!(out.account_signature_key.is_empty(), "account key must be nulled");
        assert_eq!(out.device_signature.len(), 64);

        // The device signature must verify against OUR identity over [6,1]||details||idPub||acctKey.
        let mut device_msg = vec![6u8, 1];
        device_msg.extend_from_slice(&inner_bytes);
        device_msg.extend_from_slice(&device.identity_key.public);
        device_msg.extend_from_slice(&account_pub);
        let sig: [u8; 64] = out.device_signature.as_slice().try_into().unwrap();
        assert!(wasignal::verify(&device.identity_key.public, &device_msg, &sig));
    }

    #[test]
    fn pair_success_rejects_tampered_hmac() {
        let device = DeviceIdentity::generate();
        let (mut container_bytes, _, _) = build_server_device_identity(&device);
        // Flip a byte deep in the buffer (within the HMAC region).
        let n = container_bytes.len();
        container_bytes[n - 1] ^= 0x01;
        assert!(complete_pair_success(&container_bytes, &device).is_err());
    }
}
