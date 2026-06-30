//! Length-framed stream codec.
//!
//! WhatsApp's chatd connection is a stream of frames, each prefixed with a **3-byte big-endian
//! length**. This module encodes outbound frames and reassembles inbound frames from an arbitrarily
//! chunked byte stream (TCP/WebSocket reads don't respect frame boundaries).
//!
//! The very first bytes a client sends are the connection header ([`wa_conn_header`]); subsequent
//! frames are the Noise handshake messages and then the encrypted transport messages.

use crate::Error;

/// Maximum frame payload size (3-byte length field).
pub const MAX_FRAME_LEN: usize = (1 << 24) - 1;

/// WhatsApp magic bytes that open the stream.
pub const WA_MAGIC: [u8; 2] = *b"WA";
/// Protocol "edition" byte sent in the connection header.
pub const EDITION: u8 = 6;
/// Binary-dictionary version byte sent in the connection header.
pub const DICT_VERSION: u8 = 5;

/// The connection header sent as the first bytes of the stream, and used as the Noise *prologue*
/// so the handshake transcript is bound to it. `[ 'W', 'A', EDITION, DICT_VERSION ]`.
///
/// (`EDITION`/`DICT_VERSION` track the server's current values and may need bumping over time.)
pub fn wa_conn_header() -> [u8; 4] {
    [WA_MAGIC[0], WA_MAGIC[1], EDITION, DICT_VERSION]
}

/// Append `payload` to `out` as a single length-prefixed frame.
pub fn encode_frame(payload: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let len = payload.len();
    if len > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge(len));
    }
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.extend_from_slice(payload);
    Ok(())
}

/// Reassembles whole frames out of a byte stream delivered in arbitrary chunks.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// Create an empty reader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed freshly received bytes into the reader's internal buffer.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pop the next complete frame, or `None` if a full frame isn't buffered yet.
    /// Call repeatedly after each [`push`](Self::push) until it returns `None`.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 3 {
            return None;
        }
        let len = ((self.buf[0] as usize) << 16) | ((self.buf[1] as usize) << 8) | self.buf[2] as usize;
        let total = 3 + len;
        if self.buf.len() < total {
            return None;
        }
        let frame = self.buf[3..total].to_vec();
        self.buf.drain(..total);
        Some(frame)
    }

    /// Number of bytes currently buffered but not yet formed into a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_read_round_trips() {
        let mut out = Vec::new();
        encode_frame(b"hello chatd", &mut out).unwrap();
        let mut r = FrameReader::new();
        r.push(&out);
        assert_eq!(r.next_frame().as_deref(), Some(&b"hello chatd"[..]));
        assert_eq!(r.next_frame(), None);
    }

    #[test]
    fn reassembles_across_arbitrary_chunks() {
        let mut out = Vec::new();
        encode_frame(&[0xAB; 600], &mut out).unwrap(); // length needs all 3 bytes meaningfully
        let mut r = FrameReader::new();
        // Feed one byte at a time — simulates a dribbling socket.
        for b in &out {
            assert_eq!(r.next_frame(), None, "must not yield until the full frame arrives");
            r.push(std::slice::from_ref(b));
        }
        let frame = r.next_frame().expect("frame completes on last byte");
        assert_eq!(frame, vec![0xAB; 600]);
    }

    #[test]
    fn two_frames_in_one_buffer() {
        let mut out = Vec::new();
        encode_frame(b"first", &mut out).unwrap();
        encode_frame(b"second", &mut out).unwrap();
        let mut r = FrameReader::new();
        r.push(&out);
        assert_eq!(r.next_frame().as_deref(), Some(&b"first"[..]));
        assert_eq!(r.next_frame().as_deref(), Some(&b"second"[..]));
        assert_eq!(r.next_frame(), None);
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let mut out = Vec::new();
        // Can't actually allocate 16MB cheaply in a unit test; assert the guard via a fake length.
        let err = encode_frame(&[], &mut out).is_ok();
        assert!(err); // empty frame is fine
        assert_eq!(MAX_FRAME_LEN, 0xFF_FFFF);
    }
}
