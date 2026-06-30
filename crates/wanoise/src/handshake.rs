//! The WhatsApp Noise handshake (`Noise_XX_25519_AESGCM_SHA256`) and the post-handshake
//! encrypted transport.
//!
//! WhatsApp authenticates and encrypts its chatd connection with the Noise Protocol Framework,
//! pattern **XX**, using X25519 for DH, AES-GCM for AEAD, and SHA-256 for hashing. The
//! [`wa_conn_header`](crate::frame::wa_conn_header) is fed in as the Noise *prologue*.
//!
//! The XX pattern is a three-message exchange:
//! 1. **`-> e`**          client sends its ephemeral public key.
//! 2. **`<- e, ee, s, es`** server sends ephemeral + its static key (its identity), encrypted.
//! 3. **`-> s, se`**      client sends *its* static key plus a payload — for WhatsApp this payload
//!    is the serialized `ClientPayload` protobuf (login or registration). That protobuf is owned by
//!    the (forthcoming) `waproto`/`waclient` crates, so it is passed in here as opaque bytes.
//!
//! After message 3 both parties derive two AEAD cipher states and switch to
//! [`Transport`] mode, where every chatd frame payload is encrypted with an incrementing nonce.
//!
//! This wrapper is transport-agnostic: it turns bytes into bytes. Wiring it to a real TCP/WebSocket
//! connection to `g.whatsapp.net` and supplying a real `ClientPayload` is the job of `waclient`.

use crate::Error;

const PARAMS: &str = "Noise_XX_25519_AESGCM_SHA256";
/// snow needs an output buffer at least as large as the biggest Noise message (64 KiB).
const MSG_BUF: usize = 65535;

/// An X25519 static identity keypair.
pub struct Keypair {
    /// 32-byte private key.
    pub private: Vec<u8>,
    /// 32-byte public key.
    pub public: Vec<u8>,
}

/// Generate a fresh X25519 static keypair for use as a device identity.
pub fn generate_keypair() -> Result<Keypair, Error> {
    let builder = snow::Builder::new(PARAMS.parse().map_err(|_| Error::BadParams)?);
    let kp = builder.generate_keypair()?;
    Ok(Keypair {
        private: kp.private,
        public: kp.public,
    })
}

/// A Noise XX handshake in progress.
pub struct Handshake {
    state: snow::HandshakeState,
}

impl Handshake {
    /// Build the **initiator** (client) side with our static private key and the given prologue
    /// (use [`wa_conn_header`](crate::frame::wa_conn_header)).
    pub fn new_initiator(static_private: &[u8], prologue: &[u8]) -> Result<Self, Error> {
        let state = snow::Builder::new(PARAMS.parse().map_err(|_| Error::BadParams)?)
            .local_private_key(static_private)
            .prologue(prologue)
            .build_initiator()?;
        Ok(Self { state })
    }

    /// Build the **responder** (server) side. Useful for tests and for understanding the exchange;
    /// the real server is Meta's. Requires the responder's static private key.
    pub fn new_responder(static_private: &[u8], prologue: &[u8]) -> Result<Self, Error> {
        let state = snow::Builder::new(PARAMS.parse().map_err(|_| Error::BadParams)?)
            .local_private_key(static_private)
            .prologue(prologue)
            .build_responder()?;
        Ok(Self { state })
    }

    /// Write the next handshake message, embedding `payload` (often empty until message 3).
    /// Returns the bytes to send (frame them with [`encode_frame`](crate::frame::encode_frame)).
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; MSG_BUF];
        let n = self.state.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Read an incoming handshake message, returning the decrypted payload it carried.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; MSG_BUF];
        let n = self.state.read_message(message, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Whether the handshake has completed (ready for [`into_transport`](Self::into_transport)).
    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// The remote party's static public key, available once it has been received (after message 2
    /// on the initiator side). This is how the client learns the server's identity.
    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.state.get_remote_static().map(<[u8]>::to_vec)
    }

    /// Finish the handshake and switch to the encrypted [`Transport`].
    pub fn into_transport(self) -> Result<Transport, Error> {
        Ok(Transport {
            state: self.state.into_transport_mode()?,
        })
    }
}

/// The established, encrypted post-handshake channel. Each call advances the AEAD nonce.
pub struct Transport {
    state: snow::TransportState,
}

impl Transport {
    /// Encrypt an outbound chatd frame payload.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // + AEAD tag
        let n = self.state.write_message(plaintext, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt an inbound chatd frame payload.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self.state.read_message(ciphertext, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::wa_conn_header;

    /// Drive a full XX handshake between a local initiator and responder (snow ↔ snow) to prove the
    /// wrapper's message sequencing, payload delivery, and transport-mode crypto are correct. This
    /// mirrors exactly what happens against the real server, minus the network and the protobuf
    /// ClientPayload contents.
    #[test]
    fn full_xx_handshake_and_transport() {
        let prologue = wa_conn_header();
        let client = generate_keypair().unwrap();
        let server = generate_keypair().unwrap();

        let mut initiator = Handshake::new_initiator(&client.private, &prologue).unwrap();
        let mut responder = Handshake::new_responder(&server.private, &prologue).unwrap();

        // msg1: -> e
        let m1 = initiator.write_message(&[]).unwrap();
        assert!(responder.read_message(&m1).unwrap().is_empty());

        // msg2: <- e, ee, s, es   (server could attach a payload; empty here)
        let m2 = responder.write_message(&[]).unwrap();
        assert!(initiator.read_message(&m2).unwrap().is_empty());

        // After msg2 the initiator knows the server's static identity.
        assert_eq!(initiator.remote_static().unwrap(), server.public);

        // msg3: -> s, se   carrying the (stand-in) ClientPayload
        let client_payload = b"<ClientPayload protobuf bytes>";
        let m3 = initiator.write_message(client_payload).unwrap();
        let got = responder.read_message(&m3).unwrap();
        assert_eq!(got, client_payload, "server must recover the client payload");

        assert!(initiator.is_handshake_finished());
        assert!(responder.is_handshake_finished());

        // Switch to transport mode and exchange encrypted frames both ways.
        let mut c_tx = initiator.into_transport().unwrap();
        let mut s_rx = responder.into_transport().unwrap();

        let ct = c_tx.encrypt(b"first stanza").unwrap();
        assert_ne!(ct, b"first stanza", "payload must actually be encrypted");
        assert_eq!(s_rx.decrypt(&ct).unwrap(), b"first stanza");

        let reply = s_rx.encrypt(b"server ack").unwrap();
        assert_eq!(c_tx.decrypt(&reply).unwrap(), b"server ack");
    }

    #[test]
    fn keypair_is_x25519_sized() {
        let kp = generate_keypair().unwrap();
        assert_eq!(kp.private.len(), 32);
        assert_eq!(kp.public.len(), 32);
    }
}
