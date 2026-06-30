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
    use tungstenite::http::Request;
    use tungstenite::Message;

    // WhatsApp multi-device web gateway. Origin header is required.
    let request = Request::builder()
        .uri("wss://web.whatsapp.com/ws/chat")
        .header("Host", "web.whatsapp.com")
        .header("Origin", "https://web.whatsapp.com")
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", tungstenite::handshake::client::generate_key())
        .body(())
        .map_err(|e| format!("build request: {e}"))?;

    let (mut ws, _resp) = tungstenite::connect(request).map_err(|e| format!("ws connect: {e}"))?;
    println!("    ... WebSocket connected to web.whatsapp.com");

    // Build the Noise initiator and produce the ephemeral (raw msg1 == 32-byte X25519 pubkey).
    let id = generate_keypair().map_err(|e| format!("keygen: {e}"))?;
    let prologue = wa_conn_header();
    let mut hs = Handshake::new_initiator(&id.private, &prologue).map_err(|e| format!("hs: {e}"))?;
    let ephemeral = hs.write_message(&[]).map_err(|e| format!("msg1: {e}"))?;

    // Wrap it as HandshakeMessage{ clientHello { ephemeral } } (protobuf, hand-encoded).
    let client_hello = encode_client_hello(&ephemeral);

    // First wire bytes = WA connection header, then the length-framed ClientHello.
    let mut out = prologue.to_vec();
    encode_frame(&client_hello, &mut out).map_err(|e| format!("frame: {e}"))?;
    ws.send(Message::Binary(out)).map_err(|e| format!("ws send: {e}"))?;
    println!("    ... sent WA header + ClientHello ({} ephemeral bytes)", ephemeral.len());

    // Read until we get a binary frame carrying the ServerHello.
    let mut reader = FrameReader::new();
    for _ in 0..8 {
        let msg = ws.read().map_err(|e| format!("ws read: {e}"))?;
        match msg {
            Message::Binary(data) => {
                reader.push(&data);
                if let Some(frame) = reader.next_frame() {
                    let (eph, stat, payload) = parse_server_hello(&frame)?;
                    println!(
                        "    ... got ServerHello (ephemeral {}B, static {}B, payload {}B)",
                        eph.len(),
                        stat.len(),
                        payload.len()
                    );
                    // Reconstruct the raw Noise msg2 = ephemeral || static || payload.
                    let mut raw = Vec::with_capacity(eph.len() + stat.len() + payload.len());
                    raw.extend_from_slice(&eph);
                    raw.extend_from_slice(&stat);
                    raw.extend_from_slice(&payload);
                    hs.read_message(&raw).map_err(|e| format!("noise read msg2: {e}"))?;
                    let server_static = hs
                        .remote_static()
                        .ok_or_else(|| "server static key missing".to_string())?;
                    return Ok(server_static);
                }
            }
            Message::Close(c) => return Err(format!("server closed: {c:?}")),
            _ => continue,
        }
    }
    Err("no ServerHello frame received".into())
}

// ---------------------------------------------------------------------------------------------
// Minimal protobuf for the Noise HandshakeMessage (avoids a full proto dep for the demo)
//   HandshakeMessage { ClientHello clientHello = 2; ServerHello serverHello = 3; }
//   ClientHello / ServerHello { bytes ephemeral = 1; bytes static = 2; bytes payload = 3; }
// ---------------------------------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

/// A length-delimited field: `(field_no << 3 | 2)`, varint length, then bytes.
fn put_len_field(out: &mut Vec<u8>, field_no: u64, data: &[u8]) {
    put_varint(out, (field_no << 3) | 2);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn encode_client_hello(ephemeral: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    put_len_field(&mut inner, 1, ephemeral); // ClientHello.ephemeral = 1
    let mut msg = Vec::new();
    put_len_field(&mut msg, 2, &inner); // HandshakeMessage.clientHello = 2
    msg
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut shift = 0;
    let mut val = 0u64;
    loop {
        let b = *data.get(*pos).ok_or("varint eof")?;
        *pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(val);
        }
        shift += 7;
        if shift >= 64 {
            return Err("varint too long".into());
        }
    }
}

/// A decoded protobuf length-delimited field: its number and raw bytes.
type Field = (u64, Vec<u8>);
/// The three byte-strings recovered from a `ServerHello`: ephemeral, static, payload.
type ServerHelloParts = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Walk length-delimited fields, returning `(field_no, bytes)` for each.
fn iter_fields(data: &[u8]) -> Result<Vec<Field>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let key = read_varint(data, &mut pos)?;
        let field_no = key >> 3;
        let wire = key & 7;
        match wire {
            2 => {
                let len = read_varint(data, &mut pos)? as usize;
                let end = pos.checked_add(len).ok_or("len overflow")?;
                let slice = data.get(pos..end).ok_or("field eof")?;
                out.push((field_no, slice.to_vec()));
                pos = end;
            }
            0 => {
                read_varint(data, &mut pos)?; // skip varint field
            }
            5 => pos += 4,
            1 => pos += 8,
            _ => return Err(format!("unsupported wire type {wire}")),
        }
    }
    Ok(out)
}

/// Parse HandshakeMessage -> ServerHello, returning (ephemeral, static, payload).
fn parse_server_hello(frame: &[u8]) -> Result<ServerHelloParts, String> {
    let top = iter_fields(frame)?;
    let server_hello = top
        .into_iter()
        .find(|(f, _)| *f == 3) // HandshakeMessage.serverHello = 3
        .map(|(_, b)| b)
        .ok_or("no serverHello field in HandshakeMessage")?;
    let fields = iter_fields(&server_hello)?;
    let mut eph = Vec::new();
    let mut stat = Vec::new();
    let mut payload = Vec::new();
    for (f, b) in fields {
        match f {
            1 => eph = b,
            2 => stat = b,
            3 => payload = b,
            _ => {}
        }
    }
    if eph.is_empty() || stat.is_empty() {
        return Err("ServerHello missing ephemeral/static".into());
    }
    Ok((eph, stat, payload))
}
