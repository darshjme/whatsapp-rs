//! Hand-rolled `Noise_XX_25519_AESGCM_SHA256`, byte-faithful to WhatsApp's implementation.
//!
//! We implement the symmetric state machine ourselves (rather than use a generic Noise crate) so
//! every byte matches WhatsApp's chatd handshake exactly and so `waclient` can drive the protobuf-
//! wrapped handshake frames and own the post-handshake transport keys. The primitives mirror
//! whatsmeow's `socket/noisehandshake.go`:
//!
//! - init hash `h` = the 32-byte protocol name `"Noise_XX_25519_AESGCM_SHA256\0\0\0\0"`, then
//!   `MixHash(prologue)` where the prologue is the `WA 06 03` connection header.
//! - `MixHash(x)`  → `h = SHA256(h || x)`.
//! - `MixKey(ikm)` → `counter = 0`; `(ck, k) = HKDF-SHA256(salt = ck, ikm, 64 bytes)`.
//! - AEAD = AES-256-GCM; nonce = `[0u8; 8] || counter.to_be_bytes()`; AD = current `h`.
//! - `Encrypt`/`Decrypt` use `h` as the GCM associated data, then `MixHash(ciphertext)`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use crate::Error;

/// The 32-byte Noise protocol name (`≤ 32` bytes → zero-padded to the hash length), used directly
/// as the initial handshake hash.
const NOISE_PROTOCOL_NAME: &[u8; 32] = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00";

/// Generate an X25519 keypair, returning `(private, public)`.
pub fn keypair() -> ([u8; 32], [u8; 32]) {
    let mut private = [0u8; 32];
    getrandom::getrandom(&mut private).expect("system RNG unavailable");
    let public = x25519(private, X25519_BASEPOINT_BYTES);
    (private, public)
}

/// X25519 Diffie–Hellman. The scalar is clamped internally (consistent with [`keypair`]).
pub fn dh(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    x25519(*secret, *public)
}

fn sha256_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// `HKDF-SHA256(salt, ikm)` expanded to 64 bytes, split into two 32-byte halves.
fn hkdf_two(salt: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 64];
    hk.expand(&[], &mut okm).expect("hkdf expand to 64 bytes");
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first.copy_from_slice(&okm[..32]);
    second.copy_from_slice(&okm[32..]);
    (first, second)
}

fn to_array32(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::BadLength("expected 32-byte key"))
}

/// The Noise symmetric state (hash, chaining key, current AEAD key, nonce counter).
pub struct NoiseState {
    hash: [u8; 32],
    chaining_key: [u8; 32],
    key: Option<Aes256Gcm>,
    counter: u32,
}

impl NoiseState {
    /// Initialize with the given prologue (the `WA 06 03` connection header for WhatsApp).
    pub fn new(prologue: &[u8]) -> Self {
        let mut state = NoiseState {
            hash: *NOISE_PROTOCOL_NAME,
            chaining_key: *NOISE_PROTOCOL_NAME,
            key: None,
            counter: 0,
        };
        state.mix_hash(prologue);
        state
    }

    /// `MixHash`: fold `data` into the running transcript hash.
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.hash = sha256_concat(&self.hash, data);
    }

    /// `MixKey`: derive a fresh chaining key + AEAD key from `ikm`, resetting the nonce counter.
    pub fn mix_key(&mut self, ikm: &[u8]) {
        self.counter = 0;
        let (ck, k) = hkdf_two(&self.chaining_key, ikm);
        self.chaining_key = ck;
        self.key = Some(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k)));
    }

    /// `MixKey(DH(secret, public))`.
    pub fn mix_dh(&mut self, secret: &[u8; 32], public: &[u8; 32]) {
        let shared = dh(secret, public);
        self.mix_key(&shared);
    }

    fn nonce(counter: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[8..].copy_from_slice(&counter.to_be_bytes());
        iv
    }

    /// `EncryptAndHash`: AEAD-seal `plaintext` (AD = current hash), then MixHash the ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self.key.clone().ok_or(Error::NoiseUninitialized)?;
        let ad = self.hash;
        let n = self.counter;
        self.counter += 1;
        let ciphertext = key
            .encrypt(
                Nonce::from_slice(&Self::nonce(n)),
                Payload {
                    msg: plaintext,
                    aad: &ad,
                },
            )
            .map_err(|_| Error::Crypto("aead encrypt failed"))?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    /// `DecryptAndHash`: AEAD-open `ciphertext` (AD = current hash), then MixHash the ciphertext.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self.key.clone().ok_or(Error::NoiseUninitialized)?;
        let ad = self.hash;
        let n = self.counter;
        self.counter += 1;
        let plaintext = key
            .decrypt(
                Nonce::from_slice(&Self::nonce(n)),
                Payload {
                    msg: ciphertext,
                    aad: &ad,
                },
            )
            .map_err(|_| Error::Crypto("aead decrypt/verify failed"))?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// The current transcript hash (the channel binding once the handshake completes).
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.hash
    }

    /// `Split`: derive the two directional transport keys, `(send, recv)` for the initiator.
    pub fn split(&self) -> ([u8; 32], [u8; 32]) {
        hkdf_two(&self.chaining_key, &[])
    }
}

/// The client (initiator) side of the WhatsApp XX handshake, through reading `ServerHello`.
///
/// Driving the protobuf-wrapped `ClientHello`/`ServerHello`/`ClientFinish` frames and the final
/// `ClientPayload` (login/registration) belongs to `waclient`; this type owns the Noise crypto.
pub struct XxInitiator {
    state: NoiseState,
    ephemeral_private: [u8; 32],
    ephemeral_public: [u8; 32],
    server_ephemeral: Option<[u8; 32]>,
}

impl XxInitiator {
    /// Begin the handshake: generate the ephemeral and MixHash it (Noise `-> e`).
    pub fn new(prologue: &[u8]) -> Self {
        let mut state = NoiseState::new(prologue);
        let (ephemeral_private, ephemeral_public) = keypair();
        state.mix_hash(&ephemeral_public);
        XxInitiator {
            state,
            ephemeral_private,
            ephemeral_public,
            server_ephemeral: None,
        }
    }

    /// The client ephemeral public key to place in the `ClientHello`.
    pub fn ephemeral(&self) -> [u8; 32] {
        self.ephemeral_public
    }

    /// Process `ServerHello` (`<- e, ee, s, es`): MixHash the server ephemeral, mix `ee`, decrypt
    /// the server's **static identity key**, mix `es`, decrypt the server payload (cert chain).
    /// Returns `(server_static_key, server_payload)`.
    pub fn read_server_hello(
        &mut self,
        server_ephemeral: &[u8],
        encrypted_static: &[u8],
        encrypted_payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let server_eph = to_array32(server_ephemeral)?;
        self.state.mix_hash(&server_eph);
        self.state.mix_dh(&self.ephemeral_private, &server_eph);
        let server_static = self.state.decrypt(encrypted_static)?;
        let server_static_arr = to_array32(&server_static)?;
        self.state.mix_dh(&self.ephemeral_private, &server_static_arr);
        let payload = self.state.decrypt(encrypted_payload)?;
        self.server_ephemeral = Some(server_eph);
        Ok((server_static, payload))
    }

    /// Complete the handshake (Noise `-> s, se`): encrypt our static (noise) public key, mix `se`,
    /// encrypt the `ClientPayload`, and split into the post-handshake [`NoiseTransport`]. Returns the
    /// `(encrypted_static, encrypted_payload)` to place in a `ClientFinish`, plus the transport.
    ///
    /// Must be called after [`read_server_hello`](Self::read_server_hello).
    pub fn finish(
        &mut self,
        static_private: &[u8; 32],
        static_public: &[u8; 32],
        client_payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, NoiseTransport), Error> {
        let server_eph = self
            .server_ephemeral
            .ok_or(Error::Crypto("server hello not read yet"))?;
        let encrypted_static = self.state.encrypt(static_public)?;
        self.state.mix_dh(static_private, &server_eph); // se
        let encrypted_payload = self.state.encrypt(client_payload)?;
        let (send, recv) = self.state.split();
        Ok((
            encrypted_static,
            encrypted_payload,
            NoiseTransport::new(send, recv),
        ))
    }
}

/// An established post-handshake channel: AES-256-GCM with independent send/recv nonce counters and
/// no associated data (matching whatsmeow's `NoiseSocket`).
pub struct NoiseTransport {
    send_key: Aes256Gcm,
    send_counter: u32,
    recv_key: Aes256Gcm,
    recv_counter: u32,
}

impl NoiseTransport {
    /// Build from the two directional keys produced by [`NoiseState::split`].
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        NoiseTransport {
            send_key: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&send_key)),
            send_counter: 0,
            recv_key: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&recv_key)),
            recv_counter: 0,
        }
    }

    /// Encrypt an outbound frame payload.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let n = self.send_counter;
        self.send_counter += 1;
        self.send_key
            .encrypt(Nonce::from_slice(&NoiseState::nonce(n)), plaintext)
            .map_err(|_| Error::Crypto("transport encrypt failed"))
    }

    /// Decrypt an inbound frame payload.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let n = self.recv_counter;
        self.recv_counter += 1;
        self.recv_key
            .decrypt(Nonce::from_slice(&NoiseState::nonce(n)), ciphertext)
            .map_err(|_| Error::Crypto("transport decrypt failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_name_is_exactly_32_bytes() {
        assert_eq!(NOISE_PROTOCOL_NAME.len(), 32);
    }

    #[test]
    fn dh_is_symmetric() {
        let (a_priv, a_pub) = keypair();
        let (b_priv, b_pub) = keypair();
        assert_eq!(dh(&a_priv, &b_pub), dh(&b_priv, &a_pub));
    }

    /// Full two-party XX handshake driven entirely by our own NoiseState, exercising every
    /// operation (mix_hash, ee/es/se DH, encrypt, decrypt) the way WhatsApp's server would. Proves
    /// the implementation is self-consistent: matching transcript hashes and working transport.
    #[test]
    fn full_xx_handshake_matches_and_transports() {
        let prologue = [b'W', b'A', 6, 3];

        // Static identities.
        let (i_s_priv, i_s_pub) = keypair();
        let (r_s_priv, r_s_pub) = keypair();

        let mut i = NoiseState::new(&prologue);
        let mut r = NoiseState::new(&prologue);

        // msg1  -> e
        let (i_e_priv, i_e_pub) = keypair();
        i.mix_hash(&i_e_pub);
        r.mix_hash(&i_e_pub);

        // msg2  <- e, ee, s, es  (+ server payload)
        let (r_e_priv, r_e_pub) = keypair();
        r.mix_hash(&r_e_pub);
        r.mix_dh(&r_e_priv, &i_e_pub); // ee
        let enc_static = r.encrypt(&r_s_pub).unwrap();
        r.mix_dh(&r_s_priv, &i_e_pub); // es
        let server_payload = b"<server certificate>";
        let enc_payload = r.encrypt(server_payload).unwrap();

        i.mix_hash(&r_e_pub);
        i.mix_dh(&i_e_priv, &r_e_pub); // ee
        let got_static = i.decrypt(&enc_static).unwrap();
        assert_eq!(got_static, r_s_pub, "initiator recovers server static");
        let r_s_pub_arr: [u8; 32] = got_static.clone().try_into().unwrap();
        i.mix_dh(&i_e_priv, &r_s_pub_arr); // es
        let got_payload = i.decrypt(&enc_payload).unwrap();
        assert_eq!(got_payload, server_payload);

        // msg3  -> s, se  (+ client payload)
        let enc_client_static = i.encrypt(&i_s_pub).unwrap();
        i.mix_dh(&i_s_priv, &r_e_pub); // se
        let client_payload = b"<ClientPayload>";
        let enc_client_payload = i.encrypt(client_payload).unwrap();

        let got_client_static = r.decrypt(&enc_client_static).unwrap();
        assert_eq!(got_client_static, i_s_pub);
        let i_s_pub_arr: [u8; 32] = got_client_static.try_into().unwrap();
        r.mix_dh(&r_e_priv, &i_s_pub_arr); // se
        let got_client_payload = r.decrypt(&enc_client_payload).unwrap();
        assert_eq!(got_client_payload, client_payload);

        // Transcripts converge.
        assert_eq!(i.handshake_hash(), r.handshake_hash());

        // Split + transport both directions.
        let (i_send, i_recv) = i.split();
        let (r_send, r_recv) = r.split();
        assert_eq!(i_send, r_send);
        assert_eq!(i_recv, r_recv);

        let mut client = NoiseTransport::new(i_send, i_recv);
        let mut server = NoiseTransport::new(r_recv, r_send); // mirror: server send=i_recv
        let ct = client.encrypt(b"first stanza").unwrap();
        assert_eq!(server.decrypt(&ct).unwrap(), b"first stanza");
        let reply = server.encrypt(b"server ack").unwrap();
        assert_eq!(client.decrypt(&reply).unwrap(), b"server ack");
    }

    #[test]
    fn xx_initiator_helper_drives_client_side() {
        let prologue = [b'W', b'A', 6, 3];
        // Stand up a responder by hand and check XxInitiator agrees.
        let (r_s_priv, r_s_pub) = keypair();
        let mut i = XxInitiator::new(&prologue);
        let i_e_pub = i.ephemeral();

        let mut r = NoiseState::new(&prologue);
        r.mix_hash(&i_e_pub);
        let (r_e_priv, r_e_pub) = keypair();
        r.mix_hash(&r_e_pub);
        r.mix_dh(&r_e_priv, &i_e_pub);
        let enc_static = r.encrypt(&r_s_pub).unwrap();
        r.mix_dh(&r_s_priv, &i_e_pub);
        let enc_payload = r.encrypt(b"cert").unwrap();

        let (server_static, payload) = i
            .read_server_hello(&r_e_pub, &enc_static, &enc_payload)
            .unwrap();
        assert_eq!(server_static, r_s_pub);
        assert_eq!(payload, b"cert");
    }

    #[test]
    fn xx_initiator_finish_produces_working_transport() {
        let prologue = [b'W', b'A', 6, 3];
        let (r_s_priv, r_s_pub) = keypair();
        let (c_s_priv, c_s_pub) = keypair(); // client noise static identity

        let mut i = XxInitiator::new(&prologue);
        let i_e = i.ephemeral();

        // Responder through ServerHello.
        let mut r = NoiseState::new(&prologue);
        r.mix_hash(&i_e);
        let (r_e_priv, r_e_pub) = keypair();
        r.mix_hash(&r_e_pub);
        r.mix_dh(&r_e_priv, &i_e);
        let enc_static = r.encrypt(&r_s_pub).unwrap();
        r.mix_dh(&r_s_priv, &i_e);
        let enc_payload = r.encrypt(b"cert").unwrap();
        i.read_server_hello(&r_e_pub, &enc_static, &enc_payload).unwrap();

        // Client msg3.
        let (c_enc_static, c_enc_payload, mut client_tp) =
            i.finish(&c_s_priv, &c_s_pub, b"<ClientPayload>").unwrap();

        // Responder processes msg3.
        let got = r.decrypt(&c_enc_static).unwrap();
        assert_eq!(got, c_s_pub, "server recovers client static");
        let cs: [u8; 32] = got.try_into().unwrap();
        r.mix_dh(&r_e_priv, &cs); // se
        assert_eq!(r.decrypt(&c_enc_payload).unwrap(), b"<ClientPayload>");

        // Transports must agree.
        let (rs_out1, rs_out2) = r.split();
        let mut server_tp = NoiseTransport::new(rs_out2, rs_out1);
        let ct = client_tp.encrypt(b"first stanza").unwrap();
        assert_eq!(server_tp.decrypt(&ct).unwrap(), b"first stanza");
    }
}
