//! The ADV (Auxiliary Device Verification) protobufs used in `pair-success`.
//!
//! When the phone authorizes the link, the server sends a `<pair-success>` IQ whose
//! `<device-identity>` carries a marshaled [`AdvSignedDeviceIdentityHmac`]. The client verifies it,
//! signs the device identity with its own identity key, and returns the result. Schema + field
//! numbers from whatsmeow's `proto/waAdv/WAAdv.proto`:
//!
//! ```proto
//! message ADVSignedDeviceIdentityHMAC { bytes details = 1; bytes HMAC = 2; ADVEncryptionType accountType = 3; }
//! message ADVSignedDeviceIdentity     { bytes details = 1; bytes accountSignatureKey = 2;
//!                                       bytes accountSignature = 3; bytes deviceSignature = 4; }
//! message ADVDeviceIdentity { uint32 rawID = 1; uint64 timestamp = 2; uint32 keyIndex = 3;
//!                             ADVEncryptionType accountType = 4; ADVDeviceType deviceType = 5; }
//! enum ADVEncryptionType { E2EE = 0; HOSTED = 1; }
//! ```

use crate::pb::{first_bytes, first_varint, parse, put_len_field};
use crate::Error;

/// `ADVEncryptionType::HOSTED` (E2EE is 0).
pub const ENC_TYPE_HOSTED: u64 = 1;

/// The HMAC-wrapped signed device identity sent by the server in `<pair-success>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvSignedDeviceIdentityHmac {
    pub details: Vec<u8>,
    pub hmac: Vec<u8>,
    pub account_type: u64,
}

impl AdvSignedDeviceIdentityHmac {
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let f = parse(data)?;
        Ok(AdvSignedDeviceIdentityHmac {
            details: first_bytes(&f, 1).unwrap_or_default().to_vec(),
            hmac: first_bytes(&f, 2).unwrap_or_default().to_vec(),
            account_type: first_varint(&f, 3).unwrap_or(0),
        })
    }

    /// Encode (used by tests / a mock server).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_len_field(&mut b, 1, &self.details);
        put_len_field(&mut b, 2, &self.hmac);
        if self.account_type != 0 {
            crate::pb::put_varint_field(&mut b, 3, self.account_type);
        }
        b
    }
}

/// The signed device identity: `details` (an [`AdvDeviceIdentity`]), the account's signature, and —
/// once we add it — our device signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdvSignedDeviceIdentity {
    pub details: Vec<u8>,
    pub account_signature_key: Vec<u8>,
    pub account_signature: Vec<u8>,
    pub device_signature: Vec<u8>,
}

impl AdvSignedDeviceIdentity {
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let f = parse(data)?;
        Ok(AdvSignedDeviceIdentity {
            details: first_bytes(&f, 1).unwrap_or_default().to_vec(),
            account_signature_key: first_bytes(&f, 2).unwrap_or_default().to_vec(),
            account_signature: first_bytes(&f, 3).unwrap_or_default().to_vec(),
            device_signature: first_bytes(&f, 4).unwrap_or_default().to_vec(),
        })
    }

    /// Encode in field-number order, omitting empty fields. After we sign, `account_signature_key`
    /// is cleared (whatsmeow nulls it before sending the self-signed identity back).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_len_field(&mut b, 1, &self.details);
        if !self.account_signature_key.is_empty() {
            put_len_field(&mut b, 2, &self.account_signature_key);
        }
        if !self.account_signature.is_empty() {
            put_len_field(&mut b, 3, &self.account_signature);
        }
        if !self.device_signature.is_empty() {
            put_len_field(&mut b, 4, &self.device_signature);
        }
        b
    }
}

/// The inner device identity. We mainly need `key_index` (for the response stanza attribute) and
/// `device_type` (to pick the hosted vs E2EE signature prefix).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdvDeviceIdentity {
    pub raw_id: u32,
    pub timestamp: u64,
    pub key_index: u32,
    pub account_type: u64,
    pub device_type: u64,
}

impl AdvDeviceIdentity {
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let f = parse(data)?;
        Ok(AdvDeviceIdentity {
            raw_id: first_varint(&f, 1).unwrap_or(0) as u32,
            timestamp: first_varint(&f, 2).unwrap_or(0),
            key_index: first_varint(&f, 3).unwrap_or(0) as u32,
            account_type: first_varint(&f, 4).unwrap_or(0),
            device_type: first_varint(&f, 5).unwrap_or(0),
        })
    }

    /// Encode (used by tests / a mock server).
    pub fn encode(&self) -> Vec<u8> {
        use crate::pb::put_varint_field;
        let mut b = Vec::new();
        put_varint_field(&mut b, 1, u64::from(self.raw_id));
        put_varint_field(&mut b, 2, self.timestamp);
        put_varint_field(&mut b, 3, u64::from(self.key_index));
        if self.account_type != 0 {
            put_varint_field(&mut b, 4, self.account_type);
        }
        if self.device_type != 0 {
            put_varint_field(&mut b, 5, self.device_type);
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_identity_round_trips() {
        let d = AdvDeviceIdentity {
            raw_id: 12345,
            timestamp: 1_700_000_000,
            key_index: 7,
            account_type: 0,
            device_type: 0,
        };
        assert_eq!(AdvDeviceIdentity::decode(&d.encode()).unwrap(), d);
    }

    #[test]
    fn signed_identity_round_trips_and_omits_empty() {
        let s = AdvSignedDeviceIdentity {
            details: vec![1, 2, 3],
            account_signature_key: vec![4; 32],
            account_signature: vec![5; 64],
            device_signature: Vec::new(),
        };
        let decoded = AdvSignedDeviceIdentity::decode(&s.encode()).unwrap();
        assert_eq!(decoded, s);
        // device_signature stays absent (empty) on the wire.
        assert!(decoded.device_signature.is_empty());
    }

    #[test]
    fn hmac_container_round_trips() {
        let h = AdvSignedDeviceIdentityHmac {
            details: vec![9; 50],
            hmac: vec![8; 32],
            account_type: 0,
        };
        assert_eq!(AdvSignedDeviceIdentityHmac::decode(&h.encode()).unwrap(), h);
    }
}
