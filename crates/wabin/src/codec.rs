//! Lossless encoder/decoder between [`Node`] trees and the WhatsApp binary node format.

use crate::token::{tag, token_index, token_str};
use crate::{Error, Node, NodeContent, Result};

// ----------------------------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------------------------

/// Serialize a [`Node`] into its binary-XMPP byte representation.
pub fn marshal(node: &Node) -> Result<Vec<u8>> {
    let mut enc = Encoder { buf: Vec::new() };
    enc.write_node(node)?;
    Ok(enc.buf)
}

/// Parse a single [`Node`] from a binary-XMPP byte buffer.
pub fn unmarshal(data: &[u8]) -> Result<Node> {
    let mut dec = Decoder { data, pos: 0 };
    dec.read_node()
}

// ----------------------------------------------------------------------------------------------
// Encoder
// ----------------------------------------------------------------------------------------------

struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    fn write_node(&mut self, n: &Node) -> Result<()> {
        let has_content = n.content.is_present();
        let size = 1 + n.attrs.len() * 2 + usize::from(has_content);
        self.write_list_start(size);
        self.write_string(&n.tag)?;
        for (k, v) in &n.attrs {
            self.write_string(k)?;
            self.write_string(v)?;
        }
        match &n.content {
            NodeContent::None => {}
            NodeContent::Bytes(b) => self.write_binary(b)?,
            NodeContent::Nodes(children) => {
                self.write_list_start(children.len());
                for c in children {
                    self.write_node(c)?;
                }
            }
        }
        Ok(())
    }

    fn write_list_start(&mut self, size: usize) {
        if size == 0 {
            self.buf.push(tag::LIST_EMPTY);
        } else if size < 256 {
            self.buf.push(tag::LIST_8);
            self.buf.push(size as u8);
        } else {
            self.buf.push(tag::LIST_16);
            self.buf.extend_from_slice(&(size as u16).to_be_bytes());
        }
    }

    fn write_string(&mut self, s: &str) -> Result<()> {
        if s.is_empty() {
            self.buf.push(tag::LIST_EMPTY); // token index 0 == ""
            return Ok(());
        }
        if let Some(idx) = token_index(s) {
            self.buf.push(idx);
            return Ok(());
        }
        if let Some((user, server)) = split_jid(s) {
            return self.write_jid_pair(user, server);
        }
        if is_all_nibble(s) {
            self.write_packed(s, false);
            return Ok(());
        }
        if is_all_hex(s) {
            self.write_packed(s, true);
            return Ok(());
        }
        self.write_binary(s.as_bytes())
    }

    fn write_jid_pair(&mut self, user: &str, server: &str) -> Result<()> {
        self.buf.push(tag::JID_PAIR);
        if user.is_empty() {
            self.buf.push(tag::LIST_EMPTY);
        } else {
            self.write_string(user)?;
        }
        self.write_string(server)
    }

    fn write_binary(&mut self, b: &[u8]) -> Result<()> {
        let len = b.len();
        if len < 256 {
            self.buf.push(tag::BINARY_8);
            self.buf.push(len as u8);
        } else if len < (1 << 20) {
            self.buf.push(tag::BINARY_20);
            self.buf.push(((len >> 16) & 0xff) as u8);
            self.buf.push(((len >> 8) & 0xff) as u8);
            self.buf.push((len & 0xff) as u8);
        } else if len <= u32::MAX as usize {
            self.buf.push(tag::BINARY_32);
            self.buf.extend_from_slice(&(len as u32).to_be_bytes());
        } else {
            return Err(Error::TooLarge(len));
        }
        self.buf.extend_from_slice(b);
        Ok(())
    }

    /// Pack a numeric (`NIBBLE_8`) or hex (`HEX_8`) string two characters per byte.
    fn write_packed(&mut self, s: &str, hex: bool) {
        self.buf.push(if hex { tag::HEX_8 } else { tag::NIBBLE_8 });
        let bytes = s.as_bytes();
        let len = bytes.len();
        let n_bytes = len.div_ceil(2);
        let odd = len % 2 == 1;
        let start = (n_bytes as u8) | if odd { 0x80 } else { 0 };
        self.buf.push(start);

        let mut i = 0;
        while i + 1 < len {
            let hi = nib_value(bytes[i], hex);
            let lo = nib_value(bytes[i + 1], hex);
            self.buf.push((hi << 4) | lo);
            i += 2;
        }
        if odd {
            let hi = nib_value(bytes[i], hex);
            // Only nibble runs can be odd (hex packing requires even length); pad with 15.
            self.buf.push((hi << 4) | 0x0f);
        }
    }
}

// ----------------------------------------------------------------------------------------------
// Decoder
// ----------------------------------------------------------------------------------------------

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn read_u8(&mut self) -> Result<u8> {
        let b = *self.data.get(self.pos).ok_or(Error::Eof(self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_u16(&mut self) -> Result<usize> {
        let hi = self.read_u8()? as usize;
        let lo = self.read_u8()? as usize;
        Ok((hi << 8) | lo)
    }

    fn read_u20(&mut self) -> Result<usize> {
        let a = self.read_u8()? as usize;
        let b = self.read_u8()? as usize;
        let c = self.read_u8()? as usize;
        Ok(((a & 0x0f) << 16) | (b << 8) | c)
    }

    fn read_u32(&mut self) -> Result<usize> {
        let mut v = 0usize;
        for _ in 0..4 {
            v = (v << 8) | self.read_u8()? as usize;
        }
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let end = self.pos.checked_add(n).ok_or(Error::Eof(self.pos))?;
        let slice = self.data.get(self.pos..end).ok_or(Error::Eof(self.pos))?;
        let out = slice.to_vec();
        self.pos = end;
        Ok(out)
    }

    fn read_list_size(&mut self, tag: u8) -> Result<usize> {
        match tag {
            tag::LIST_EMPTY => Ok(0),
            tag::LIST_8 => Ok(self.read_u8()? as usize),
            tag::LIST_16 => self.read_u16(),
            other => Err(Error::InvalidNode(format!("expected list tag, got {other}"))),
        }
    }

    fn read_node(&mut self) -> Result<Node> {
        let list_tag = self.read_u8()?;
        let size = self.read_list_size(list_tag)?;
        if size == 0 {
            return Err(Error::InvalidNode("zero-size node".into()));
        }
        let desc_tag = self.read_u8()?;
        if desc_tag == tag::STREAM_END {
            return Err(Error::InvalidNode("unexpected stream end".into()));
        }
        let tag_name = self.read_string(desc_tag)?;
        let attr_count = (size - 1) / 2;
        let mut attrs = Vec::with_capacity(attr_count);
        for _ in 0..attr_count {
            let kt = self.read_u8()?;
            let key = self.read_string(kt)?;
            let vt = self.read_u8()?;
            let value = self.read_string(vt)?;
            attrs.push((key, value));
        }
        let content = if size % 2 == 1 {
            NodeContent::None
        } else {
            self.read_content()?
        };
        Ok(Node {
            tag: tag_name,
            attrs,
            content,
        })
    }

    fn read_content(&mut self) -> Result<NodeContent> {
        let t = self.read_u8()?;
        match t {
            tag::LIST_EMPTY | tag::LIST_8 | tag::LIST_16 => {
                let n = self.read_list_size(t)?;
                let mut children = Vec::with_capacity(n);
                for _ in 0..n {
                    children.push(self.read_node()?);
                }
                Ok(NodeContent::Nodes(children))
            }
            tag::BINARY_8 => {
                let n = self.read_u8()? as usize;
                Ok(NodeContent::Bytes(self.read_bytes(n)?))
            }
            tag::BINARY_20 => {
                let n = self.read_u20()?;
                Ok(NodeContent::Bytes(self.read_bytes(n)?))
            }
            tag::BINARY_32 => {
                let n = self.read_u32()?;
                Ok(NodeContent::Bytes(self.read_bytes(n)?))
            }
            other => Err(Error::InvalidNode(format!("bad content tag {other}"))),
        }
    }

    fn read_string(&mut self, t: u8) -> Result<String> {
        match t {
            0..=235 => token_str(t as usize)
                .map(str::to_owned)
                .ok_or(Error::UnknownToken(t as usize)),
            tag::DICTIONARY_0..=tag::DICTIONARY_3 => {
                // Double-byte dictionaries: index follows in the next byte. Not yet seeded, so we
                // consume the index and report it rather than corrupting the stream position.
                let idx = self.read_u8()? as usize;
                let dict = (t - tag::DICTIONARY_0) as usize;
                Err(Error::UnknownToken(dict * 256 + idx))
            }
            tag::AD_JID => self.read_ad_jid(),
            tag::JID_PAIR => self.read_jid_pair(),
            tag::HEX_8 => self.read_packed(true),
            tag::NIBBLE_8 => self.read_packed(false),
            tag::BINARY_8 => {
                let n = self.read_u8()? as usize;
                self.read_utf8(n)
            }
            tag::BINARY_20 => {
                let n = self.read_u20()?;
                self.read_utf8(n)
            }
            tag::BINARY_32 => {
                let n = self.read_u32()?;
                self.read_utf8(n)
            }
            other => Err(Error::InvalidNode(format!(
                "tag {other} is not valid in a string position"
            ))),
        }
    }

    fn read_utf8(&mut self, n: usize) -> Result<String> {
        let bytes = self.read_bytes(n)?;
        String::from_utf8(bytes).map_err(|_| Error::Utf8)
    }

    fn read_jid_pair(&mut self) -> Result<String> {
        let ut = self.read_u8()?;
        let user = self.read_string(ut)?;
        let st = self.read_u8()?;
        let server = self.read_string(st)?;
        Ok(format!("{user}@{server}"))
    }

    fn read_ad_jid(&mut self) -> Result<String> {
        // Agent/device-addressed JID: agent byte, device byte, then the user string.
        let _agent = self.read_u8()?;
        let device = self.read_u8()?;
        let ut = self.read_u8()?;
        let user = self.read_string(ut)?;
        if device == 0 {
            Ok(format!("{user}@s.whatsapp.net"))
        } else {
            Ok(format!("{user}.{device}@s.whatsapp.net"))
        }
    }

    fn read_packed(&mut self, hex: bool) -> Result<String> {
        let start = self.read_u8()?;
        let odd = start & 0x80 != 0;
        let n = (start & 0x7f) as usize;
        let bytes = self.read_bytes(n)?;
        let mut s = String::with_capacity(n * 2);
        for (idx, b) in bytes.iter().enumerate() {
            let hi = (b >> 4) & 0x0f;
            let lo = b & 0x0f;
            s.push(nib_char(hi, hex));
            let is_last = idx == n - 1;
            if is_last && odd && !hex && lo == 0x0f {
                // padding nibble on an odd-length numeric run: drop it
            } else {
                s.push(nib_char(lo, hex));
            }
        }
        Ok(s)
    }
}

// ----------------------------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------------------------

/// Split `"user@server"` into its parts. Returns `None` if there is no `@`.
fn split_jid(s: &str) -> Option<(&str, &str)> {
    s.find('@').map(|i| (&s[..i], &s[i + 1..]))
}

/// A numeric run packable with `NIBBLE_8`: digits plus `-` and `.`, bounded so the byte length
/// fits the 7-bit packed-length field.
fn is_all_nibble(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 254
        && s.bytes()
            .all(|c| c.is_ascii_digit() || c == b'-' || c == b'.')
}

/// An (even-length, uppercase) hex run packable with `HEX_8`. Even-length only, so odd runs never
/// need an ambiguous pad nibble; uppercase only, so decoding round-trips exactly.
fn is_all_hex(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 254
        && s.len() % 2 == 0
        && s.bytes().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
}

/// Map a character to its 4-bit packed value.
fn nib_value(c: u8, hex: bool) -> u8 {
    if hex {
        match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    } else {
        match c {
            b'0'..=b'9' => c - b'0',
            b'-' => 10,
            b'.' => 11,
            _ => 0,
        }
    }
}

/// Map a 4-bit packed value back to its character.
fn nib_char(v: u8, hex: bool) -> char {
    if hex {
        match v {
            0..=9 => (b'0' + v) as char,
            10..=15 => (b'A' + v - 10) as char,
            _ => '\0',
        }
    } else {
        match v {
            0..=9 => (b'0' + v) as char,
            10 => '-',
            11 => '.',
            _ => '\0',
        }
    }
}

// ----------------------------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(node: &Node) -> Node {
        let bytes = marshal(node).expect("marshal");
        unmarshal(&bytes).expect("unmarshal")
    }

    #[test]
    fn message_stanza_round_trips() {
        let node = Node::new("message")
            .attr("to", "12345@s.whatsapp.net")
            .attr("type", "text")
            .attr("id", "ABCD1234")
            .children(vec![Node::new("body").bytes(&b"hello world"[..])]);
        assert_eq!(round_trip(&node), node);
    }

    #[test]
    fn tokens_are_compressed() {
        // "message"=11, "to"=14, "type"=4, "id"=8 are dictionary tokens; "s.whatsapp.net"=3.
        let node = Node::new("message")
            .attr("to", "1@s.whatsapp.net")
            .attr("type", "text");
        let bytes = marshal(&node).unwrap();
        // list8 tag + size, then the description token must be the single byte 11.
        assert_eq!(bytes[0], tag::LIST_8);
        assert_eq!(bytes[2], 11, "description should encode as token 11 (message)");
        assert_eq!(round_trip(&node), node);
    }

    #[test]
    fn nibble_and_hex_packing_round_trip() {
        let node = Node::new("test")
            .attr("phone", "1234567890")       // even nibble
            .attr("odd", "12345")              // odd nibble (pad-trim path)
            .attr("dashed", "123-456.7")       // nibble with - and .
            .attr("hex", "DEADBEEF");          // even uppercase hex
        assert_eq!(round_trip(&node), node);
    }

    #[test]
    fn jid_pair_round_trips() {
        let node = Node::new("iq")
            .attr("from", "9876543210@s.whatsapp.net")
            .attr("group", "12345-67890@g.us");
        assert_eq!(round_trip(&node), node);
    }

    #[test]
    fn nested_children_and_empty_content() {
        let node = Node::new("iq").attr("type", "result").children(vec![
            Node::new("list").children(vec![
                Node::new("item").attr("jid", "1@s.whatsapp.net"),
                Node::new("item").attr("jid", "2@s.whatsapp.net"),
            ]),
            Node::new("ping"), // self-closing, no content
        ]);
        assert_eq!(round_trip(&node), node);
    }

    #[test]
    fn large_binary_uses_20bit_length() {
        let big = vec![0x42u8; 5000]; // > 255, < 1<<20  -> BINARY_20
        let node = Node::new("enc").bytes(big);
        let bytes = marshal(&node).unwrap();
        assert!(bytes.contains(&tag::BINARY_20));
        assert_eq!(round_trip(&node), node);
    }

    #[test]
    fn empty_string_attr_round_trips() {
        let node = Node::new("presence").attr("from", "").attr("status", "");
        assert_eq!(round_trip(&node), node);
    }

    #[test]
    fn truncated_input_errors_cleanly() {
        let node = Node::new("message").bytes(&b"payload"[..]);
        let bytes = marshal(&node).unwrap();
        // Chop the buffer; decoding must error, not panic.
        let err = unmarshal(&bytes[..bytes.len() - 3]);
        assert!(err.is_err());
    }
}
