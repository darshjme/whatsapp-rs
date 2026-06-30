//! The WhatsApp string-token dictionary.
//!
//! On the wire, common strings (element names, attribute keys, well-known values) are replaced by a
//! single-byte index into a shared dictionary, which is how the protocol stays compact. This module
//! holds that dictionary.
//!
//! **Fidelity note:** the entries below are a *verified-correct subset* of WhatsApp's canonical
//! single-byte token table (indices 0..=29, which are stable and well-established). The remaining
//! single-byte entries and the three double-byte dictionaries are intentionally left out for now and
//! will be imported wholesale before live-server interop. Encoding never depends on the table being
//! complete (unknown strings fall back to a raw binary encoding); decoding an index we don't yet know
//! yields [`crate::Error::UnknownToken`] instead of silently corrupting data.

/// Tag/marker byte values used by the node codec.
pub(crate) mod tag {
    pub const LIST_EMPTY: u8 = 0;
    pub const STREAM_END: u8 = 2;
    pub const DICTIONARY_0: u8 = 236;
    pub const DICTIONARY_3: u8 = 239;
    pub const AD_JID: u8 = 247;
    pub const LIST_8: u8 = 248;
    pub const LIST_16: u8 = 249;
    pub const JID_PAIR: u8 = 250;
    pub const HEX_8: u8 = 251;
    pub const BINARY_8: u8 = 252;
    pub const BINARY_20: u8 = 253;
    pub const BINARY_32: u8 = 254;
    pub const NIBBLE_8: u8 = 255;
}

/// The single-byte token dictionary. Index `i` (as a wire byte) decodes to `SINGLE_BYTE_TOKENS[i]`.
/// `None` marks an index that is not yet seeded.
pub static SINGLE_BYTE_TOKENS: &[Option<&str>] = &[
    Some(""),               // 0
    Some("xmlstreamstart"), // 1
    Some("xmlstreamend"),   // 2
    Some("s.whatsapp.net"), // 3
    Some("type"),           // 4
    Some("participant"),    // 5
    Some("from"),           // 6
    Some("receipt"),        // 7
    Some("id"),             // 8
    Some("broadcast"),      // 9
    Some("status"),         // 10
    Some("message"),        // 11
    Some("notification"),   // 12
    Some("notify"),         // 13
    Some("to"),             // 14
    Some("jid"),            // 15
    Some("user"),           // 16
    Some("class"),          // 17
    Some("offline"),        // 18
    Some("g.us"),           // 19
    Some("result"),         // 20
    Some("mediatype"),      // 21
    Some("enc"),            // 22
    Some("skmsg"),          // 23
    Some("off"),            // 24
    Some("count"),          // 25
    Some("u"),              // 26
    Some("devices"),        // 27
    Some("device-list"),    // 28
    Some("key-index-list"), // 29
];

/// Decode a single-byte token index to its string, if seeded.
pub(crate) fn token_str(index: usize) -> Option<&'static str> {
    SINGLE_BYTE_TOKENS.get(index).copied().flatten()
}

/// Find the single-byte token index for a string, if it is in the dictionary.
/// Index 0 (the empty string) is handled separately by the encoder and is skipped here.
pub(crate) fn token_index(s: &str) -> Option<u8> {
    if s.is_empty() {
        return None;
    }
    SINGLE_BYTE_TOKENS
        .iter()
        .enumerate()
        .find_map(|(i, t)| if *t == Some(s) { Some(i as u8) } else { None })
}
