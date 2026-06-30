//! The Noise `HandshakeMessage` family.
//!
//! WhatsApp wraps each raw Noise XX message in a protobuf so the server can demultiplex the three
//! handshake stages. The schema (field numbers verified against WhatsApp's `WAWebProtobufsWa6` /
//! whatsmeow's `waE2E`/`waWa6` definitions):
//!
//! ```proto
//! message HandshakeMessage {
//!   message ClientHello  { bytes ephemeral = 1; bytes static = 2; bytes payload = 3; }
//!   message ServerHello  { bytes ephemeral = 1; bytes static = 2; bytes payload = 3; }
//!   message ClientFinish { bytes static   = 1; bytes payload = 2; }
//!   ClientHello  clientHello  = 2;
//!   ServerHello  serverHello  = 3;
//!   ClientFinish clientFinish = 4;
//! }
//! ```

use crate::pb::{get_field, iter_len_fields, put_len_field};
use crate::Error;

// HandshakeMessage field numbers.
const F_CLIENT_HELLO: u64 = 2;
const F_SERVER_HELLO: u64 = 3;
const F_CLIENT_FINISH: u64 = 4;
// Inner field numbers (ClientHello / ServerHello).
const F_EPHEMERAL: u64 = 1;
const F_STATIC: u64 = 2;
const F_PAYLOAD: u64 = 3;
// ClientFinish inner field numbers.
const F_CF_STATIC: u64 = 1;
const F_CF_PAYLOAD: u64 = 2;

/// Message 1: `-> e`. Only `ephemeral` is set during a standard XX handshake.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHello {
    pub ephemeral: Vec<u8>,
    pub static_key: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Message 2: `<- e, ee, s, es`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerHello {
    pub ephemeral: Vec<u8>,
    pub static_key: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Message 3: `-> s, se` carrying the encrypted `ClientPayload`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientFinish {
    pub static_key: Vec<u8>,
    pub payload: Vec<u8>,
}

impl ClientHello {
    /// A message-1 ClientHello carrying just the Noise ephemeral public key (the raw output of the
    /// initiator's first `write_message`).
    pub fn with_ephemeral(ephemeral: impl Into<Vec<u8>>) -> Self {
        ClientHello {
            ephemeral: ephemeral.into(),
            ..Default::default()
        }
    }

    fn encode_inner(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_len_field(&mut b, F_EPHEMERAL, &self.ephemeral);
        if !self.static_key.is_empty() {
            put_len_field(&mut b, F_STATIC, &self.static_key);
        }
        if !self.payload.is_empty() {
            put_len_field(&mut b, F_PAYLOAD, &self.payload);
        }
        b
    }

    /// Encode as a complete `HandshakeMessage`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_len_field(&mut out, F_CLIENT_HELLO, &self.encode_inner());
        out
    }
}

impl ServerHello {
    fn decode_inner(bytes: &[u8]) -> Result<Self, Error> {
        let fields = iter_len_fields(bytes)?;
        let eph = get_field(&fields, F_EPHEMERAL).unwrap_or_default().to_vec();
        let stat = get_field(&fields, F_STATIC).unwrap_or_default().to_vec();
        let payload = get_field(&fields, F_PAYLOAD).unwrap_or_default().to_vec();
        if eph.is_empty() || stat.is_empty() {
            return Err(Error::Malformed("ServerHello missing ephemeral or static"));
        }
        Ok(ServerHello {
            ephemeral: eph,
            static_key: stat,
            payload,
        })
    }

    /// Encode as a complete `HandshakeMessage` (used by tests / a mock server).
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        put_len_field(&mut inner, F_EPHEMERAL, &self.ephemeral);
        put_len_field(&mut inner, F_STATIC, &self.static_key);
        if !self.payload.is_empty() {
            put_len_field(&mut inner, F_PAYLOAD, &self.payload);
        }
        let mut out = Vec::new();
        put_len_field(&mut out, F_SERVER_HELLO, &inner);
        out
    }

    /// Reassemble the raw Noise message-2 bytes (`ephemeral || static || payload`) that the Noise
    /// state machine expects to read.
    pub fn noise_message(&self) -> Vec<u8> {
        let mut raw =
            Vec::with_capacity(self.ephemeral.len() + self.static_key.len() + self.payload.len());
        raw.extend_from_slice(&self.ephemeral);
        raw.extend_from_slice(&self.static_key);
        raw.extend_from_slice(&self.payload);
        raw
    }
}

impl ClientFinish {
    /// A message-3 ClientFinish: the encrypted static key plus the encrypted `ClientPayload`.
    pub fn new(static_key: impl Into<Vec<u8>>, payload: impl Into<Vec<u8>>) -> Self {
        ClientFinish {
            static_key: static_key.into(),
            payload: payload.into(),
        }
    }

    /// Encode as a complete `HandshakeMessage`.
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        put_len_field(&mut inner, F_CF_STATIC, &self.static_key);
        put_len_field(&mut inner, F_CF_PAYLOAD, &self.payload);
        let mut out = Vec::new();
        put_len_field(&mut out, F_CLIENT_FINISH, &inner);
        out
    }
}

/// Parse a `HandshakeMessage` and return whichever stage it carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    ClientFinish(ClientFinish),
}

impl HandshakeMessage {
    /// Decode a `HandshakeMessage`, dispatching on which oneof field is present.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let fields = iter_len_fields(bytes)?;
        if let Some(sh) = get_field(&fields, F_SERVER_HELLO) {
            return Ok(HandshakeMessage::ServerHello(ServerHello::decode_inner(sh)?));
        }
        if let Some(ch) = get_field(&fields, F_CLIENT_HELLO) {
            let inner = iter_len_fields(ch)?;
            return Ok(HandshakeMessage::ClientHello(ClientHello {
                ephemeral: get_field(&inner, F_EPHEMERAL).unwrap_or_default().to_vec(),
                static_key: get_field(&inner, F_STATIC).unwrap_or_default().to_vec(),
                payload: get_field(&inner, F_PAYLOAD).unwrap_or_default().to_vec(),
            }));
        }
        if let Some(cf) = get_field(&fields, F_CLIENT_FINISH) {
            let inner = iter_len_fields(cf)?;
            return Ok(HandshakeMessage::ClientFinish(ClientFinish {
                static_key: get_field(&inner, F_CF_STATIC).unwrap_or_default().to_vec(),
                payload: get_field(&inner, F_CF_PAYLOAD).unwrap_or_default().to_vec(),
            }));
        }
        Err(Error::Malformed("HandshakeMessage has no known stage"))
    }

    /// Convenience: extract a `ServerHello`, or error if this wasn't one.
    pub fn into_server_hello(self) -> Result<ServerHello, Error> {
        match self {
            HandshakeMessage::ServerHello(s) => Ok(s),
            _ => Err(Error::Malformed("expected ServerHello")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_round_trips_through_handshake_message() {
        let ch = ClientHello::with_ephemeral(vec![7u8; 32]);
        let decoded = HandshakeMessage::decode(&ch.encode()).unwrap();
        assert_eq!(decoded, HandshakeMessage::ClientHello(ch));
    }

    #[test]
    fn server_hello_round_trips_and_reassembles_noise_message() {
        let sh = ServerHello {
            ephemeral: vec![1u8; 32],
            static_key: vec![2u8; 48], // 32 + 16-byte AEAD tag
            payload: vec![3u8; 90],
        };
        let decoded = HandshakeMessage::decode(&sh.encode())
            .unwrap()
            .into_server_hello()
            .unwrap();
        assert_eq!(decoded, sh);
        let raw = decoded.noise_message();
        assert_eq!(raw.len(), 32 + 48 + 90);
        assert_eq!(&raw[..32], &[1u8; 32]);
        assert_eq!(&raw[32..80], &[2u8; 48]);
    }

    #[test]
    fn client_finish_round_trips() {
        let cf = ClientFinish::new(vec![9u8; 48], vec![5u8; 120]);
        let decoded = HandshakeMessage::decode(&cf.encode()).unwrap();
        assert_eq!(decoded, HandshakeMessage::ClientFinish(cf));
    }

    #[test]
    fn server_hello_requires_static() {
        // ephemeral only -> not a valid ServerHello
        let mut inner = Vec::new();
        crate::pb::put_len_field(&mut inner, F_EPHEMERAL, &[0u8; 32]);
        let mut msg = Vec::new();
        crate::pb::put_len_field(&mut msg, F_SERVER_HELLO, &inner);
        assert!(HandshakeMessage::decode(&msg).is_err());
    }
}
