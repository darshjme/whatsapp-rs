//! The persisted session: the device identity plus, once paired, the account state needed to log
//! back in and operate as a linked device.

use serde::{Deserialize, Serialize};

use crate::device::DeviceIdentity;
use crate::Error;

/// The paired-account state (populated after a successful pair-success / companion_finish).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    /// Our own device JID, e.g. `447700900123:23@s.whatsapp.net`.
    pub jid: String,
    /// The `@lid` addressing JID, if the server provided one.
    #[serde(default)]
    pub lid: Option<String>,
    /// The account (phone) identity public key from the signed device identity.
    #[serde(with = "b64_vec")]
    pub account_signature_key: Vec<u8>,
    /// Our self-signed `ADVSignedDeviceIdentity` (proves this device is authorized).
    #[serde(with = "b64_vec")]
    pub signed_device_identity: Vec<u8>,
    #[serde(default)]
    pub push_name: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub business_name: Option<String>,
}

/// A full session: device identity + optional paired account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub device: DeviceIdentity,
    #[serde(default)]
    pub account: Option<Account>,
}

impl Session {
    /// A fresh, unpaired session for a new device identity.
    pub fn new(device: DeviceIdentity) -> Self {
        Session { device, account: None }
    }

    /// Whether this session has completed pairing (and can log in instead of registering).
    pub fn is_paired(&self) -> bool {
        self.account.is_some()
    }

    /// Serialize to pretty JSON (the on-disk session file).
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Store(e.to_string()))
    }

    /// Load from the JSON produced by [`to_json`](Self::to_json).
    pub fn from_json(s: &str) -> Result<Self, Error> {
        serde_json::from_str(s).map_err(|e| Error::Store(e.to_string()))
    }
}

/// serde helper: `Vec<u8>` <-> base64 string.
mod b64_vec {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpaired_session_round_trips() {
        let s = Session::new(DeviceIdentity::generate());
        assert!(!s.is_paired());
        let back = Session::from_json(&s.to_json().unwrap()).unwrap();
        assert_eq!(back.device, s.device);
        assert!(back.account.is_none());
    }

    #[test]
    fn paired_session_round_trips() {
        let mut s = Session::new(DeviceIdentity::generate());
        s.account = Some(Account {
            jid: "447700900123:23@s.whatsapp.net".into(),
            lid: Some("111:23@lid".into()),
            account_signature_key: vec![1u8; 32],
            signed_device_identity: vec![2u8; 120],
            push_name: Some("Chatbot".into()),
            platform: Some("android".into()),
            business_name: None,
        });
        let back = Session::from_json(&s.to_json().unwrap()).unwrap();
        assert!(back.is_paired());
        let a = back.account.unwrap();
        assert_eq!(a.jid, "447700900123:23@s.whatsapp.net");
        assert_eq!(a.account_signature_key, vec![1u8; 32]);
        assert_eq!(a.signed_device_identity.len(), 120);
    }
}
