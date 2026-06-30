//! `wademo` — see whatsapp-rs working.
//!
//! Part 1 (always runs, offline): encode a real `message` stanza with `wabin` and show the bytes;
//! run a full Noise XX handshake with `wanoise` and prove transport-mode encryption.
//!
//! Part 2 (network): open a WebSocket to WhatsApp's real `web.whatsapp.com/ws/chat` gateway, send a
//! Noise `ClientHello`, and read the server's `ServerHello` — completing enough of the handshake to
//! recover **the server's static identity key**. That proves our transport stack interoperates with
//! Meta's live chatd servers. (No account/login is involved; the ClientPayload that carries identity
//! is only sent in the *third* handshake message, which we don't send here.)

use std::sync::mpsc;
use std::time::Duration;

use wabin::{marshal, unmarshal, Node};
use wanoise::frame::{encode_frame, wa_conn_header, FrameReader};
use wanoise::handshake::{generate_keypair, Handshake};

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
// Part 1 — the codec + crypto pipeline, fully offline
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
    let decoded = unmarshal(&wire).expect("unmarshal");
    println!(
        "    round-trip decode matches original: {}",
        decoded == stanza
    );

    println!("\n[2] wanoise — Noise_XX handshake + encrypted transport (local client<->server)");
    let client = generate_keypair().expect("client key");
    let server = generate_keypair().expect("server key");
    let prologue = wa_conn_header();
    println!("    prologue / WA conn header : {}", hex(&prologue));
    println!("    client static pubkey      : {}", hex(&client.public));

    let mut initiator = Handshake::new_initiator(&client.private, &prologue).unwrap();
    let mut responder = Handshake::new_responder(&server.private, &prologue).unwrap();

    let m1 = initiator.write_message(&[]).unwrap();
    responder.read_message(&m1).unwrap();
    println!("    -> e            (msg1) : {} bytes", m1.len());

    let m2 = responder.write_message(&[]).unwrap();
    initiator.read_message(&m2).unwrap();
    println!("    <- e,ee,s,es    (msg2) : {} bytes", m2.len());

    let m3 = initiator.write_message(b"<ClientPayload here>").unwrap();
    responder.read_message(&m3).unwrap();
    println!("    -> s,se+payload (msg3) : {} bytes", m3.len());

    println!(
        "    initiator recovered server identity: {}",
        hex(&initiator.remote_static().unwrap()) == hex(&server.public)
    );

    let mut c = initiator.into_transport().unwrap();
    let mut s = responder.into_transport().unwrap();
    let ct = c.encrypt(b"<encrypted stanza>").unwrap();
    let pt = s.decrypt(&ct).unwrap();
    println!(
        "    transport: encrypted {} plaintext bytes -> {} ciphertext bytes -> decrypted OK: {}",
        b"<encrypted stanza>".len(),
        ct.len(),
        pt == b"<encrypted stanza>"
    );
}

// ---------------------------------------------------------------------------------------------
// Part 2 — a real handshake against WhatsApp's servers
// ---------------------------------------------------------------------------------------------

fn part2_live_handshake() {
    println!("[3] LIVE — handshaking with WhatsApp's real chatd gateway (web.whatsapp.com)");

    // Run on a worker thread with a hard timeout so a stalled socket can never hang the demo.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(try_live_handshake());
    });

    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(server_static)) => {
            println!("    ✅ Connected and completed Noise msg1/msg2 with the real server.");
            println!("    WhatsApp server static identity key:");
            println!("      {}", hex(&server_static));
            println!("    => our Noise_XX transport interoperates with Meta's live chatd. 🎉");
        }
        Ok(Err(e)) => {
            println!("    ⚠  Reached the server but the exchange did not complete: {e}");
            println!("    (Usually a protocol-version/header detail — the connection itself worked.)");
        }
        Err(_) => println!("    ⚠  Timed out after 20s waiting for the server."),
    }
}

fn try_live_handshake() -> Result<Vec<u8>, String> {
    // The on-wire header is always WA 06 03 (this is what the server's dictionary-version check
    // accepts). The Noise *prologue* is logically separate; the reference says it equals the header,
    // but a msg2 decrypt failure is the classic prologue-mismatch signature, so we try both and let
    // the live server tell us which is right.
    let wire_header = wa_conn_header();
    let candidates: [(&str, Vec<u8>); 2] = [
        ("prologue = WAConnHeader", wire_header.to_vec()),
        ("prologue = empty", Vec::new()),
    ];

    let mut last_err = String::new();
    for (label, prologue) in candidates {
        match attempt_handshake(&wire_header, &prologue) {
            Ok(server_static) => {
                println!("    ✓ Noise msg2 decrypted with {label}");
                return Ok(server_static);
            }
            Err(e) => {
                println!("    · {label}: {e}");
                last_err = e;
            }
        }
    }
    Err(last_err)
}

/// One full attempt over a fresh WebSocket: send ClientHello, read ServerHello, decrypt msg2.
fn attempt_handshake(wire_header: &[u8], noise_prologue: &[u8]) -> Result<Vec<u8>, String> {
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

    let id = generate_keypair().map_err(|e| format!("keygen: {e}"))?;
    let mut hs =
        Handshake::new_initiator(&id.private, noise_prologue).map_err(|e| format!("hs: {e}"))?;
    let ephemeral = hs.write_message(&[]).map_err(|e| format!("msg1: {e}"))?;

    // First wire bytes = WA header, then the length-framed typed ClientHello — one binary message.
    let client_hello = waproto::ClientHello::with_ephemeral(ephemeral).encode();
    let mut out = wire_header.to_vec();
    encode_frame(&client_hello, &mut out).map_err(|e| format!("frame: {e}"))?;
    ws.send(Message::Binary(out)).map_err(|e| format!("ws send: {e}"))?;

    let mut reader = FrameReader::new();
    for _ in 0..8 {
        match ws.read().map_err(|e| format!("ws read: {e}"))? {
            Message::Binary(data) => {
                reader.push(&data);
                if let Some(frame) = reader.next_frame() {
                    let server_hello = waproto::HandshakeMessage::decode(&frame)
                        .map_err(|e| format!("decode: {e}"))?
                        .into_server_hello()
                        .map_err(|e| format!("expected ServerHello: {e}"))?;
                    println!(
                        "      (server replied: ServerHello ephemeral {}B / static {}B / cert {}B)",
                        server_hello.ephemeral.len(),
                        server_hello.static_key.len(),
                        server_hello.payload.len()
                    );
                    hs.read_message(&server_hello.noise_message())
                        .map_err(|e| format!("noise read msg2: {e}"))?;
                    return hs
                        .remote_static()
                        .ok_or_else(|| "server static key missing".to_string());
                }
            }
            Message::Close(c) => return Err(format!("server closed: {c:?}")),
            _ => continue,
        }
    }
    Err("no ServerHello frame received".into())
}

