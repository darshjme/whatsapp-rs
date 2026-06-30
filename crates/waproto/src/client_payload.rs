//! The registration `ClientPayload` — the protobuf sent (encrypted) in Noise message 3 to register
//! a new companion device.
//!
//! Field numbers and values are taken verbatim from whatsmeow's `store/clientpayload.go` and the
//! `WAWebProtobufsWa6` / `WACompanionReg` protos. We only ever *encode* this (the client sends it),
//! so this is an encoder, not a full message type.
//!
//! Layout:
//! ```text
//! ClientPayload {
//!   userAgent       = 5  { platform=WEB(14), appVersion={2,3000,1041871181}, mcc/mnc="000",
//!                          osVersion="0.1", device="Desktop", osBuildNumber="0.1",
//!                          releaseChannel=RELEASE(0), locale "en"/"US" }
//!   webInfo         = 6  { webSubPlatform=WEB_BROWSER(0) }
//!   connectType     = 12 = WIFI_UNKNOWN(1)
//!   connectReason   = 13 = USER_ACTIVATED(1)
//!   devicePairingData = 19 (DevicePairingRegistrationData)
//!   passive         = 3  = false
//!   pull            = 33 = false
//! }
//! ```

use crate::pb::{put_len_field, put_varint_field};

/// Default WhatsApp-web version advertised in `userAgent.appVersion` (the canonical companion path).
/// NOTE: this is whatsmeow-main's pinned value and is currently stale — the live server rejects it
/// with `<failure reason="405">` (client out of date). Override at runtime with a current value via
/// `WAPAIR_VERSION` until a fresh default is wired in. Must match `build_hash` (MD5 of "p.s.t").
pub const WA_VERSION: (u64, u64, u64) = (2, 3000, 1_041_871_181);

/// Default UserAgent platform enum value. WEB=14, WINDOWS=13. Override via `WAPAIR_PLATFORM`.
pub const WA_PLATFORM: u64 = 14;

/// Inputs needed to build a registration `ClientPayload` from a device identity.
pub struct RegistrationPayload {
    pub registration_id: u32,
    pub signed_pre_key_id: u32,
    pub identity_public: [u8; 32],
    pub signed_pre_key_public: [u8; 32],
    /// 64-byte XEdDSA signature over `0x05 || signed_pre_key_public`.
    pub signed_pre_key_signature: Vec<u8>,
    /// MD5 of the version string (16 bytes), e.g. `MD5("2.3000.1041871181")`.
    pub build_hash: [u8; 16],
    /// The device label shown in the phone's linked-devices list (DeviceProps.os).
    pub device_os: String,
    /// `userAgent.appVersion` = (primary, secondary, tertiary). Must match `build_hash`.
    pub app_version: (u64, u64, u64),
    /// `userAgent.platform` enum (WEB=14, WINDOWS=13, …).
    pub platform: u64,
}

fn app_version(p: u64, s: u64, t: u64) -> Vec<u8> {
    let mut b = Vec::new();
    put_varint_field(&mut b, 1, p);
    put_varint_field(&mut b, 2, s);
    put_varint_field(&mut b, 3, t);
    b
}

fn user_agent(version: (u64, u64, u64), platform: u64) -> Vec<u8> {
    let (p, s, t) = version;
    let mut b = Vec::new();
    put_varint_field(&mut b, 1, platform); // platform
    put_len_field(&mut b, 2, &app_version(p, s, t)); // appVersion
    put_len_field(&mut b, 3, b"000"); // mcc
    put_len_field(&mut b, 4, b"000"); // mnc
    put_len_field(&mut b, 5, b"0.1"); // osVersion
    put_len_field(&mut b, 6, b""); // manufacturer
    put_len_field(&mut b, 7, b"Desktop"); // device
    put_len_field(&mut b, 8, b"0.1"); // osBuildNumber
    put_varint_field(&mut b, 10, 0); // releaseChannel = RELEASE
    put_len_field(&mut b, 11, b"en"); // localeLanguageIso6391
    put_len_field(&mut b, 12, b"US"); // localeCountryIso31661Alpha2
    b
}

fn web_info() -> Vec<u8> {
    let mut b = Vec::new();
    put_varint_field(&mut b, 1, 0); // webSubPlatform = WEB_BROWSER
    b
}

fn device_props(os: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_len_field(&mut b, 1, os.as_bytes()); // os (the device label)
    put_len_field(&mut b, 2, &app_version(0, 1, 0)); // version = 0.1.0
    put_varint_field(&mut b, 3, 0); // platformType = UNKNOWN
    put_varint_field(&mut b, 4, 0); // requireFullSync = false
    b
}

impl RegistrationPayload {
    fn device_pairing_data(&self) -> Vec<u8> {
        let reg_id = self.registration_id.to_be_bytes(); // 4-byte BE
        let skey_id = self.signed_pre_key_id.to_be_bytes(); // take low 3 bytes
        let mut b = Vec::new();
        put_len_field(&mut b, 1, &reg_id); // eRegid
        put_len_field(&mut b, 2, &[0x05]); // eKeytype = DJB
        put_len_field(&mut b, 3, &self.identity_public); // eIdent
        put_len_field(&mut b, 4, &skey_id[1..]); // eSkeyId (3-byte BE)
        put_len_field(&mut b, 5, &self.signed_pre_key_public); // eSkeyVal
        put_len_field(&mut b, 6, &self.signed_pre_key_signature); // eSkeySig
        put_len_field(&mut b, 7, &self.build_hash); // buildHash
        put_len_field(&mut b, 8, &device_props(&self.device_os)); // companionProps
        b
    }

    /// Encode the complete registration `ClientPayload`.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_len_field(&mut b, 5, &user_agent(self.app_version, self.platform));
        put_len_field(&mut b, 6, &web_info());
        put_varint_field(&mut b, 12, 1); // connectType = WIFI_UNKNOWN
        put_varint_field(&mut b, 13, 1); // connectReason = USER_ACTIVATED
        put_len_field(&mut b, 19, &self.device_pairing_data());
        put_varint_field(&mut b, 3, 0); // passive = false
        put_varint_field(&mut b, 33, 0); // pull = false
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::{get_field, iter_len_fields};

    fn sample() -> RegistrationPayload {
        RegistrationPayload {
            registration_id: 0x0102_0304,
            signed_pre_key_id: 1,
            identity_public: [0x11; 32],
            signed_pre_key_public: [0x22; 32],
            signed_pre_key_signature: vec![0x33; 64],
            build_hash: [0x44; 16],
            device_os: "whatsapp-rs".into(),
            app_version: WA_VERSION,
            platform: WA_PLATFORM,
        }
    }

    #[test]
    fn encodes_expected_top_level_fields() {
        let bytes = sample().encode();
        let fields = iter_len_fields(&bytes).unwrap();
        assert!(get_field(&fields, 5).is_some(), "userAgent present");
        assert!(get_field(&fields, 6).is_some(), "webInfo present");
        assert!(get_field(&fields, 19).is_some(), "devicePairingData present");
    }

    #[test]
    fn registration_data_carries_correct_keys_and_sizes() {
        let p = sample();
        let bytes = p.encode();
        let top = iter_len_fields(&bytes).unwrap();
        let reg = get_field(&top, 19).unwrap();
        let reg_fields = iter_len_fields(reg).unwrap();

        assert_eq!(get_field(&reg_fields, 1), Some(&[1, 2, 3, 4][..]), "eRegid 4-byte BE");
        assert_eq!(get_field(&reg_fields, 2), Some(&[0x05][..]), "eKeytype DJB");
        assert_eq!(get_field(&reg_fields, 3), Some(&[0x11; 32][..]), "eIdent");
        assert_eq!(get_field(&reg_fields, 4), Some(&[0, 0, 1][..]), "eSkeyId 3-byte BE");
        assert_eq!(get_field(&reg_fields, 5).unwrap().len(), 32, "eSkeyVal");
        assert_eq!(get_field(&reg_fields, 6).unwrap().len(), 64, "eSkeySig");
        assert_eq!(get_field(&reg_fields, 7).unwrap().len(), 16, "buildHash");
        assert!(get_field(&reg_fields, 8).is_some(), "deviceProps");
    }
}
