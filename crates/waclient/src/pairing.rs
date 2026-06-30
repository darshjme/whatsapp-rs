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

use crate::device::DeviceIdentity;

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
}
