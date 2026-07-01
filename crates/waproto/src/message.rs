//! The WhatsApp `Message` protobuf — the plaintext content that gets Signal-encrypted inside an
//! `<enc>` element. This is a minimal subset (text messages) to bootstrap messaging; more message
//! types (media, reactions, etc.) slot in as additional fields.
//!
//! Schema (whatsmeow `proto/waE2E`):
//! ```proto
//! message Message {
//!   optional string conversation = 1;                     // simple text
//!   optional ExtendedTextMessage extendedTextMessage = 6; // text + context
//!   ...
//! }
//! message ExtendedTextMessage { optional string text = 1; ... }
//! ```

use crate::pb::{first_bytes, parse, put_len_field, Value};
use crate::Error;

/// A decoded/encodable WhatsApp message (text subset for now).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// `conversation` (field 1) — a plain text message.
    pub conversation: Option<String>,
    /// `extendedTextMessage.text` (field 6 → 1) — text with (omitted) context.
    pub extended_text: Option<String>,
}

impl Message {
    /// A plain text message.
    pub fn text(body: impl Into<String>) -> Self {
        Message {
            conversation: Some(body.into()),
            extended_text: None,
        }
    }

    /// The text body, from either representation.
    pub fn text_content(&self) -> Option<&str> {
        self.conversation
            .as_deref()
            .or(self.extended_text.as_deref())
    }

    /// Encode to protobuf bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        if let Some(text) = &self.conversation {
            put_len_field(&mut b, 1, text.as_bytes());
        }
        if let Some(text) = &self.extended_text {
            let mut inner = Vec::new();
            put_len_field(&mut inner, 1, text.as_bytes());
            put_len_field(&mut b, 6, &inner);
        }
        b
    }

    /// Decode from protobuf bytes.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let fields = parse(data)?;
        let conversation = string_field(&fields, 1)?;
        let extended_text = match first_bytes(&fields, 6) {
            Some(inner) => {
                let inner_fields = parse(inner)?;
                string_field(&inner_fields, 1)?
            }
            None => None,
        };
        Ok(Message {
            conversation,
            extended_text,
        })
    }
}

fn string_field(fields: &[(u64, Value)], field_no: u64) -> Result<Option<String>, Error> {
    match first_bytes(fields, field_no) {
        Some(b) => Ok(Some(String::from_utf8(b.to_vec()).map_err(|_| Error::Malformed("non-utf8 string"))?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_round_trips() {
        let m = Message::text("hello from whatsapp-rs");
        let decoded = Message::decode(&m.encode()).unwrap();
        assert_eq!(decoded, m);
        assert_eq!(decoded.text_content(), Some("hello from whatsapp-rs"));
    }

    #[test]
    fn extended_text_round_trips() {
        let m = Message {
            conversation: None,
            extended_text: Some("rich text".into()),
        };
        let decoded = Message::decode(&m.encode()).unwrap();
        assert_eq!(decoded, m);
        assert_eq!(decoded.text_content(), Some("rich text"));
    }

    #[test]
    fn empty_message_decodes() {
        let m = Message::decode(&[]).unwrap();
        assert_eq!(m.text_content(), None);
    }
}
