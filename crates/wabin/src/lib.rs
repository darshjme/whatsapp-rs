//! # wabin — WhatsApp binary XMPP node codec
//!
//! WhatsApp's multi-device protocol does **not** use REST or plain XML on the wire. After the
//! Noise handshake, the client and the `g.whatsapp.net` ("chatd") gateway exchange a stream of
//! length-framed, token-compressed **binary XMPP nodes** (called *stanzas*). Every higher-level
//! operation — sending a message, syncing app-state, signalling a voice call — is ultimately one
//! of these [`Node`]s.
//!
//! This crate implements that node format: an in-memory [`Node`] tree plus a lossless
//! [`marshal`]/[`unmarshal`] codec. It is the foundation every other `whatsapp-rs` crate builds on.
//!
//! ## Wire format (summary)
//! A node is a *list*: `[ list-size ] [ description-token ] [ attr-key attr-value ]* [ content ]?`.
//! - **List size** uses tags `LIST_EMPTY`(0) / `LIST_8`(248, u8) / `LIST_16`(249, u16-BE). The size
//!   counts `1` (the description) `+ 2*attrs` `+ 1` if a content element follows.
//! - **Strings** are written as the cheapest of: a single-byte **token** (a shared dictionary index),
//!   a packed **NIBBLE_8**(255) / **HEX_8**(251) run, a **JID_PAIR**(250) / **AD_JID**(247), or a raw
//!   length-prefixed **BINARY_8/20/32**(252/253/254) blob.
//! - **Content** is either a nested list of child nodes, or a raw binary blob.
//!
//! ## Status
//! The codec algorithm is complete and round-trip tested. The token dictionary
//! ([`token::SINGLE_BYTE_TOKENS`]) currently ships a verified-correct *subset*; the full canonical
//! single- and double-byte tables will be imported for full server interop. Unknown token indices
//! decode to [`Error::UnknownToken`] rather than corrupting data.

#![forbid(unsafe_code)]

mod codec;
pub mod token;

pub use codec::{marshal, unmarshal};

use std::collections::BTreeMap;

/// Errors produced while encoding or decoding a [`Node`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Ran off the end of the input buffer.
    #[error("unexpected end of buffer at offset {0}")]
    Eof(usize),
    /// A structurally invalid node was encountered.
    #[error("invalid node: {0}")]
    InvalidNode(String),
    /// A token index that is not present in the (currently partial) dictionary.
    #[error("unknown token index {0}")]
    UnknownToken(usize),
    /// A value was too large to be represented by the 32-bit length field.
    #[error("value too large to encode: {0} bytes")]
    TooLarge(usize),
    /// A string field did not contain valid UTF-8.
    #[error("invalid utf-8 in string field")]
    Utf8,
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// The payload carried by a [`Node`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeContent {
    /// No content element (the node is self-closing).
    None,
    /// A raw binary blob (e.g. an encrypted message, a media pointer, a protobuf).
    Bytes(Vec<u8>),
    /// A nested list of child nodes.
    Nodes(Vec<Node>),
}

impl NodeContent {
    fn is_present(&self) -> bool {
        !matches!(self, NodeContent::None)
    }
}

/// A single binary-XMPP node (stanza element).
///
/// Attribute order is preserved on the wire and on round-trip, so attributes are stored as an
/// ordered list rather than a hash map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// The element name / description token (e.g. `"message"`, `"iq"`, `"call"`).
    pub tag: String,
    /// Ordered `(key, value)` attribute pairs.
    pub attrs: Vec<(String, String)>,
    /// The node body.
    pub content: NodeContent,
}

impl Node {
    /// Create a childless, attribute-less node with the given tag.
    pub fn new(tag: impl Into<String>) -> Self {
        Node {
            tag: tag.into(),
            attrs: Vec::new(),
            content: NodeContent::None,
        }
    }

    /// Builder: append an attribute.
    pub fn attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.push((key.into(), value.into()));
        self
    }

    /// Builder: set raw binary content.
    pub fn bytes(mut self, b: impl Into<Vec<u8>>) -> Self {
        self.content = NodeContent::Bytes(b.into());
        self
    }

    /// Builder: set child nodes.
    pub fn children(mut self, nodes: impl Into<Vec<Node>>) -> Self {
        self.content = NodeContent::Nodes(nodes.into());
        self
    }

    /// Look up an attribute value by key (first match).
    pub fn get_attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Borrow the child nodes, if this node's content is a node list.
    pub fn child_nodes(&self) -> &[Node] {
        match &self.content {
            NodeContent::Nodes(n) => n,
            _ => &[],
        }
    }

    /// Borrow the raw content bytes, if this node's content is a binary blob.
    pub fn content_bytes(&self) -> Option<&[u8]> {
        match &self.content {
            NodeContent::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Collect attributes into a map (loses ordering / duplicate keys; for convenience only).
    pub fn attr_map(&self) -> BTreeMap<&str, &str> {
        self.attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }
}
