//! Phone-number (pairing-code) linking — the "Link with phone number" method.
//!
//! Instead of a QR scan, the user enters their phone number on the companion and types an 8-char
//! code on their phone. Two phases (matching whatsmeow `pair-code.go`):
//!
//! 1. [`begin_phone_pairing`] — generate the code + an ephemeral key, wrap the ephemeral public with
//!    a PBKDF2(code) key, and produce the `companion_hello` child nodes. Show the code to the user.
//! 2. [`finish_phone_pairing`] — when the phone enters the code, the server sends the primary's
//!    wrapped ephemeral + identity key. We decrypt it, derive the shared **adv secret**, wrap a key
//!    bundle, and produce the `companion_finish` child nodes. The normal `pair-success` then follows
//!    (using the derived adv secret).

use wabin::Node;

use crate::device::DeviceIdentity;
use crate::Error;

/// The Crockford-ish base32 alphabet WhatsApp uses for the linking code (no 0/O/1/I).
const LINKING_ALPHABET: &[u8; 32] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";
/// PBKDF2 iteration count from whatsmeow (`2 << 16`).
const PBKDF2_ITERATIONS: u32 = 2 << 16;

fn fill_random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("system RNG unavailable");
    b
}

/// Encode 5 bytes (40 bits) as 8 base32 characters using the WhatsApp linking alphabet.
fn base32_encode_5(bytes: &[u8; 5]) -> String {
    let mut buffer = 0u64;
    for b in bytes {
        buffer = (buffer << 8) | u64::from(*b);
    }
    (0..8)
        .map(|i| {
            let idx = ((buffer >> (35 - i * 5)) & 0x1f) as usize;
            LINKING_ALPHABET[idx] as char
        })
        .collect()
}

/// State carried between the two phone-pairing phases.
#[derive(Clone, Debug)]
pub struct PhoneLinking {
    pub ephemeral_private: [u8; 32],
    pub ephemeral_public: [u8; 32],
    /// The raw 8-character linking code (no dash).
    pub linking_code: String,
    /// The `link_code_pairing_ref` returned by the server in phase 1.
    pub pairing_ref: Option<String>,
}

/// Phase 1: build the linking code + `companion_hello` child nodes.
/// Returns the state, the child nodes to put inside `<link_code_companion_reg stage="companion_hello">`,
/// and the user-facing code formatted as `XXXX-XXXX`.
pub fn begin_phone_pairing(
    device: &DeviceIdentity,
    client_type: &str,
    display_name: &str,
) -> (PhoneLinking, Vec<Node>, String) {
    let (ephemeral_private, ephemeral_public) = wanoise::keypair();
    let salt: [u8; 32] = fill_random();
    let iv: [u8; 16] = fill_random();
    let code_bytes: [u8; 5] = fill_random();
    let code = base32_encode_5(&code_bytes);

    let link_key: [u8; 32] = wasignal::pbkdf2_sha256(code.as_bytes(), &salt, PBKDF2_ITERATIONS, 32)
        .try_into()
        .expect("32-byte key");
    let encrypted_pub = wasignal::aes256_ctr(&link_key, &iv, &ephemeral_public);

    // wrapped ephemeral = salt(32) || iv(16) || encrypted_pub(32)
    let mut wrapped = Vec::with_capacity(80);
    wrapped.extend_from_slice(&salt);
    wrapped.extend_from_slice(&iv);
    wrapped.extend_from_slice(&encrypted_pub);

    let children = vec![
        Node::new("link_code_pairing_wrapped_companion_ephemeral_pub").bytes(wrapped),
        Node::new("companion_server_auth_key_pub").bytes(device.noise_key.public.to_vec()),
        Node::new("companion_platform_id").bytes(client_type.as_bytes().to_vec()),
        Node::new("companion_platform_display").bytes(display_name.as_bytes().to_vec()),
        Node::new("link_code_pairing_nonce").bytes(vec![0u8]),
    ];

    let formatted = format!("{}-{}", &code[..4], &code[4..]);
    (
        PhoneLinking {
            ephemeral_private,
            ephemeral_public,
            linking_code: code,
            pairing_ref: None,
        },
        children,
        formatted,
    )
}

/// Phase 2: process the code-pair notification and build the `companion_finish` child nodes.
/// Also returns the derived **adv secret**, which the caller must store on the device before the
/// `pair-success` step (which authenticates with it).
pub fn finish_phone_pairing(
    device: &DeviceIdentity,
    state: &PhoneLinking,
    wrapped_primary_ephemeral_pub: &[u8],
    primary_identity_pub: &[u8],
) -> Result<([u8; 32], Vec<Node>), Error> {
    if wrapped_primary_ephemeral_pub.len() < 80 {
        return Err(Error::Pairing("wrapped primary ephemeral pub too short"));
    }
    let primary_salt = &wrapped_primary_ephemeral_pub[0..32];
    let primary_iv: [u8; 16] = wrapped_primary_ephemeral_pub[32..48].try_into().unwrap();
    let primary_enc_pub = &wrapped_primary_ephemeral_pub[48..80];
    let primary_id: [u8; 32] = primary_identity_pub
        .try_into()
        .map_err(|_| Error::Pairing("bad primary identity pub length"))?;

    // Decrypt the primary's ephemeral pub with the PBKDF2(code) key, then DH with our ephemeral priv.
    let link_key: [u8; 32] =
        wasignal::pbkdf2_sha256(state.linking_code.as_bytes(), primary_salt, PBKDF2_ITERATIONS, 32)
            .try_into()
            .expect("32-byte key");
    let primary_pub: [u8; 32] = wasignal::aes256_ctr(&link_key, &primary_iv, primary_enc_pub)
        .as_slice()
        .try_into()
        .map_err(|_| Error::Pairing("bad decrypted primary pub"))?;
    let ephemeral_shared = wanoise::dh(&state.ephemeral_private, &primary_pub);

    // Wrap a key bundle: our identity pub, the primary identity pub, and fresh adv randomness.
    let adv_random: [u8; 32] = fill_random();
    let bundle_salt: [u8; 32] = fill_random();
    let bundle_nonce: [u8; 12] = fill_random();
    let bundle_key: [u8; 32] = wasignal::hkdf_sha256(
        &ephemeral_shared,
        &bundle_salt,
        b"link_code_pairing_key_bundle_encryption_key",
        32,
    )
    .try_into()
    .expect("32-byte key");

    let mut plaintext = Vec::with_capacity(96);
    plaintext.extend_from_slice(&device.identity_key.public);
    plaintext.extend_from_slice(&primary_id);
    plaintext.extend_from_slice(&adv_random);
    let encrypted_bundle = wasignal::aes256_gcm_seal(&bundle_key, &bundle_nonce, &plaintext);

    let mut wrapped_bundle = Vec::with_capacity(44 + encrypted_bundle.len());
    wrapped_bundle.extend_from_slice(&bundle_salt);
    wrapped_bundle.extend_from_slice(&bundle_nonce);
    wrapped_bundle.extend_from_slice(&encrypted_bundle);

    // adv secret = HKDF(ephemeralShared || identityShared || advRandom, nil, "adv_secret").
    let identity_shared = wanoise::dh(&device.identity_key.private, &primary_id);
    let mut adv_input = Vec::with_capacity(96);
    adv_input.extend_from_slice(&ephemeral_shared);
    adv_input.extend_from_slice(&identity_shared);
    adv_input.extend_from_slice(&adv_random);
    let adv_secret: [u8; 32] = wasignal::hkdf_sha256(&adv_input, b"", b"adv_secret", 32)
        .try_into()
        .expect("32-byte key");

    let children = vec![
        Node::new("link_code_pairing_wrapped_key_bundle").bytes(wrapped_bundle),
        Node::new("companion_identity_public").bytes(device.identity_key.public.to_vec()),
        Node::new("link_code_pairing_ref")
            .bytes(state.pairing_ref.clone().unwrap_or_default().into_bytes()),
    ];
    Ok((adv_secret, children))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linking_code_is_8_uppercase_base32_chars() {
        let (_, _, formatted) = begin_phone_pairing(&DeviceIdentity::generate(), "1", "Chrome (Windows)");
        // "XXXX-XXXX"
        assert_eq!(formatted.len(), 9);
        assert_eq!(formatted.chars().nth(4), Some('-'));
        let raw: String = formatted.chars().filter(|c| *c != '-').collect();
        assert!(raw.bytes().all(|b| LINKING_ALPHABET.contains(&b)));
    }

    /// Full two-phase round-trip: companion begins, a simulated primary device wraps its ephemeral
    /// with the code and replies, the companion finishes, and BOTH sides derive the SAME adv secret.
    #[test]
    fn phone_pairing_derives_matching_adv_secret() {
        let device = DeviceIdentity::generate();
        let (mut state, _hello, _code) = begin_phone_pairing(&device, "1", "Chrome (Windows)");
        state.pairing_ref = Some("ref-123".into());

        // --- simulated primary device ---
        let (primary_eph_priv, primary_eph_pub) = wanoise::keypair();
        let (primary_id_priv, primary_id_pub) = wanoise::keypair();
        // Primary wraps its ephemeral pub with the code (same scheme as the companion).
        let p_salt: [u8; 32] = [5u8; 32];
        let p_iv: [u8; 16] = [6u8; 16];
        let p_key: [u8; 32] = wasignal::pbkdf2_sha256(state.linking_code.as_bytes(), &p_salt, PBKDF2_ITERATIONS, 32)
            .try_into()
            .unwrap();
        let p_enc = wasignal::aes256_ctr(&p_key, &p_iv, &primary_eph_pub);
        let mut wrapped_primary = Vec::new();
        wrapped_primary.extend_from_slice(&p_salt);
        wrapped_primary.extend_from_slice(&p_iv);
        wrapped_primary.extend_from_slice(&p_enc);

        // --- companion finishes ---
        let (our_adv, children) =
            finish_phone_pairing(&device, &state, &wrapped_primary, &primary_id_pub).unwrap();

        // --- primary independently derives the adv secret to confirm they match ---
        // 1. recover shared secret (primary side): DH(primaryEphPriv, ourEphPub)
        let primary_ephemeral_shared = wanoise::dh(&primary_eph_priv, &state.ephemeral_public);
        // 2. decrypt our key bundle to recover advRandom
        let bundle = children
            .iter()
            .find(|n| n.tag == "link_code_pairing_wrapped_key_bundle")
            .and_then(|n| n.content_bytes())
            .unwrap();
        let b_salt = &bundle[0..32];
        let b_nonce: [u8; 12] = bundle[32..44].try_into().unwrap();
        let b_ct = &bundle[44..];
        let b_key: [u8; 32] = wasignal::hkdf_sha256(
            &primary_ephemeral_shared,
            b_salt,
            b"link_code_pairing_key_bundle_encryption_key",
            32,
        )
        .try_into()
        .unwrap();
        let recovered = wasignal::aes256_gcm_open(&b_key, &b_nonce, b_ct).unwrap();
        let adv_random = &recovered[64..96]; // our_id(32) || primary_id(32) || advRandom(32)
        // 3. primary adv secret
        let primary_identity_shared = wanoise::dh(&primary_id_priv, &device.identity_key.public);
        let mut adv_input = Vec::new();
        adv_input.extend_from_slice(&primary_ephemeral_shared);
        adv_input.extend_from_slice(&primary_identity_shared);
        adv_input.extend_from_slice(adv_random);
        let primary_adv: [u8; 32] = wasignal::hkdf_sha256(&adv_input, b"", b"adv_secret", 32)
            .try_into()
            .unwrap();

        assert_eq!(our_adv, primary_adv, "both sides must derive the same adv secret");
        // and the bundle carried the right identity keys
        assert_eq!(&recovered[0..32], &device.identity_key.public);
        assert_eq!(&recovered[32..64], &primary_id_pub);
    }
}
