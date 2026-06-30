//! `wademo` — see whatsapp-rs working.
//!
//! Part 1 (offline): encode a real `message` stanza with `wabin`; run a full hand-rolled Noise XX
//! handshake with `wanoise` and prove transport-mode encryption.
//!
//! Part 2 (network): open a WebSocket to WhatsApp's real `web.whatsapp.com/ws/chat` gateway, send a
//! Noise `ClientHello`, read the `ServerHello`, and **decrypt the server's static identity key** —
//! proving our hand-rolled Noise interoperates with Meta's live chatd servers. (No login is
//! involved; the `ClientPayload` that carries identity is only sent in the third handshake message.)

use std::sync::mpsc;
use std::time::Duration;

use wabin::{marshal, unmarshal, Node};
use wanoise::frame::{encode_frame, wa_conn_header, FrameReader};
use wanoise::noise::{keypair, NoiseState, NoiseTransport, XxInitiator};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    println!("\n=================  whatsapp-rs live demo  =================\n");
    part1_offline_pipeline();
    println!();
    part2_live_handshake();
    println!("\n==========================================================\n");
}

// ---------------------------------------------------------------------------------------------
// Part 1 — codec + hand-rolled Noise, offline
// ---------------------------------------------------------------------------------------------

fn part1_offline_pipeline() {
    println!("[1] wabin — binary-XMPP stanza codec");
    let stanza = Node::new("message")
        .attr("to", "447700900123@s.whatsapp.net")
        .attr("type", "text")
        .attr("id", "3EB0ABCD1234")
        .children(vec![Node::new("body").bytes(&b"hello from whatsapp-rs"[..])]);
    let wire = marshal(&stanza).expect("marshal");
    println!("    stanza encoded to {} bytes:", wire.len());
    println!("      {}", hex(&wire));
    println!("    round-trip decode matches: {}", unmarshal(&wire).unwrap() == stanza);

    println!("\n[2] wanoise — hand-rolled Noise_XX handshake + transport (local client<->server)");
    let prologue = wa_conn_header();
    println!("    prologue / WA conn header : {}", hex(&prologue));

    // Server identity + a by-hand responder; the client is our XxInitiator.
    let (server_s_priv, server_s_pub) = keypair();
    let mut client = XxInitiator::new(&prologue);
    let client_eph = client.ephemeral();

    let mut server = NoiseState::new(&prologue);
    server.mix_hash(&client_eph); // <- e
    let (server_e_priv, server_e_pub) = keypair();
    server.mix_hash(&server_e_pub);
    server.mix_dh(&server_e_priv, &client_eph); // ee
    let enc_static = server.encrypt(&server_s_pub).unwrap();
    server.mix_dh(&server_s_priv, &client_eph); // es
    let enc_payload = server.encrypt(b"<server certificate>").unwrap();

    let (recovered_static, cert) = client
        .read_server_hello(&server_e_pub, &enc_static, &enc_payload)
        .expect("read ServerHello");
    println!("    client ephemeral          : {}", hex(&client_eph));
    println!("    server static (sent)      : {}", hex(&server_s_pub));
    println!("    server static (recovered) : {}", hex(&recovered_static));
    println!(
        "    -> recovered server identity correctly: {}  (cert {} bytes)",
        recovered_static == server_s_pub,
        cert.len()
    );

    // Demonstrate the post-handshake transport with a fresh keyed pair.
    let (k1, k2) = (keypair().0, keypair().0); // two independent 32-byte keys
    let mut a = NoiseTransport::new(k1, k2);
    let mut b = NoiseTransport::new(k2, k1);
    let ct = a.encrypt(b"<encrypted stanza>").unwrap();
    println!(
        "    transport: {} plaintext -> {} ciphertext -> decrypts OK: {}",
        b"<encrypted stanza>".len(),
        ct.len(),
        b.decrypt(&ct).unwrap() == b"<encrypted stanza>"
    );
}

// ---------------------------------------------------------------------------------------------
// Part 2 — a real handshake against WhatsApp's servers
// ---------------------------------------------------------------------------------------------

fn part2_live_handshake() {
    println!("[3] LIVE — handshaking with WhatsApp's real chatd gateway (web.whatsapp.com)");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(try_live_handshake());
    });
    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok((server_static, cert_len))) => {
            println!("    ✅ Completed Noise msg1/msg2 with the real server and DECRYPTED its identity.");
            println!("    WhatsApp server static identity key:");
            println!("      {}", hex(&server_static));
            println!("    server certificate payload: {cert_len} bytes (encrypted cert chain)");
            println!("    => our hand-rolled Noise_XX interoperates with Meta's live chatd. 🎉");
        }
        Ok(Err(e)) => {
            println!("    ⚠  Reached the server but the exchange did not complete: {e}");
        }
        Err(_) => println!("    ⚠  Timed out after 20s waiting for the server."),
    }
}

/// Connect, send ClientHello, read ServerHello, decrypt the server static. Returns
/// `(server_static_key, cert_payload_len)`.
fn try_live_handshake() -> Result<(Vec<u8>, usize), String> {
    use tungstenite::http::Request;
    use tungstenite::Message;

    let request = Request::builder()
        .uri("wss://web.whatsapp.com/ws/chat")
        .header("Host", "web.whatsapp.com")
        .header("Origin", "https://web.whatsapp.com")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", tungstenite::handshake::client::generate_key())
        .body(())
        .map_err(|e| format!("build request: {e}"))?;

    let (mut ws, _resp) = tungstenite::connect(request).map_err(|e| format!("ws connect: {e}"))?;
    println!("    ... WebSocket connected to web.whatsapp.com");

    let prologue = wa_conn_header();
    let mut hs = XxInitiator::new(&prologue);

    // First wire bytes = WA header, then the length-framed ClientHello — in one binary message.
    let client_hello = waproto::ClientHello::with_ephemeral(hs.ephemeral().to_vec()).encode();
    let mut out = prologue.to_vec();
    encode_frame(&client_hello, &mut out).map_err(|e| format!("frame: {e}"))?;
    ws.send(Message::Binary(out)).map_err(|e| format!("ws send: {e}"))?;
    println!("    ... sent WA header + ClientHello");

    let mut reader = FrameReader::new();
    for _ in 0..8 {
        match ws.read().map_err(|e| format!("ws read: {e}"))? {
            Message::Binary(data) => {
                reader.push(&data);
                if let Some(frame) = reader.next_frame() {
                    let sh = waproto::HandshakeMessage::decode(&frame)
                        .map_err(|e| format!("decode: {e}"))?
                        .into_server_hello()
                        .map_err(|e| format!("expected ServerHello: {e}"))?;
                    println!(
                        "    ... got ServerHello (ephemeral {}B / static {}B / cert {}B)",
                        sh.ephemeral.len(),
                        sh.static_key.len(),
                        sh.payload.len()
                    );
                    let (server_static, cert) = hs
                        .read_server_hello(&sh.ephemeral, &sh.static_key, &sh.payload)
                        .map_err(|e| format!("noise read ServerHello: {e}"))?;
                    return Ok((server_static, cert.len()));
                }
            }
            Message::Close(c) => return Err(format!("server closed: {c:?}")),
            _ => continue,
        }
    }
    Err("no ServerHello frame received".into())
}
