//! `wapair` — link a WhatsApp companion device.
//!
//! Runs the full multi-device registration handshake against the live server and renders the
//! pairing QR in the terminal:
//!   1. load/generate the device identity (keystore in `wapair-session.json`),
//!   2. Noise XX handshake (msg1/msg2) — `XxInitiator`,
//!   3. send the registration `ClientPayload` as the encrypted msg3 `ClientFinish`,
//!   4. read the encrypted `pair-device` IQ over the Noise transport, extract the refs,
//!   5. print the QR. Scan it with WhatsApp on your phone (Linked devices → Link a device).
//!
//! Use a **secondary/burner number** for testing.

use std::fs;
use std::net::TcpStream;
use std::time::Duration;

use md5::{Digest, Md5};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{http::Request, Message, WebSocket};

use waclient::device::DeviceIdentity;
use wabin::Node;
use wanoise::frame::{encode_frame, wa_conn_header, FrameReader};
use wanoise::noise::XxInitiator;

const SESSION_FILE: &str = "wapair-session.json";
const DEVICE_LABEL: &str = "whatsapp-rs";

fn main() {
    println!("\n===============  wapair — link a WhatsApp device  ===============\n");
    match run() {
        Ok(()) => {}
        Err(e) => eprintln!("\n  error: {e}\n"),
    }
}

fn run() -> Result<(), String> {
    // 1. Device identity (persisted so the session is stable across runs).
    let device = load_or_create_device()?;
    println!("[*] device identity ready (registration id {})", device.registration_id);
    println!("    noise pub    : {}", b64(&device.noise_key.public));
    println!("    identity pub : {}", b64(&device.identity_key.public));

    // 2. Connect + Noise handshake.
    let mut ws = connect()?;
    set_read_timeout(&ws, Duration::from_secs(40));
    let prologue = wa_conn_header();
    let mut hs = XxInitiator::new(&prologue);
    let mut reader = FrameReader::new();

    // msg1: WA header + ClientHello (one binary message).
    let client_hello = waproto::ClientHello::with_ephemeral(hs.ephemeral().to_vec()).encode();
    let mut first = prologue.to_vec();
    encode_frame(&client_hello, &mut first).map_err(|e| e.to_string())?;
    ws.send(Message::Binary(first)).map_err(|e| format!("send ClientHello: {e}"))?;
    println!("[*] sent ClientHello, waiting for ServerHello...");

    // msg2: ServerHello.
    let server_hello = read_frame(&mut ws, &mut reader)?;
    let sh = waproto::HandshakeMessage::decode(&server_hello)
        .map_err(|e| format!("decode ServerHello: {e}"))?
        .into_server_hello()
        .map_err(|e| e.to_string())?;
    hs.read_server_hello(&sh.ephemeral, &sh.static_key, &sh.payload)
        .map_err(|e| format!("process ServerHello: {e}"))?;
    println!("[*] ServerHello accepted, server identity verified");

    // 3. msg3: registration ClientPayload -> ClientFinish.
    let payload = build_registration_payload(&device);
    let (enc_static, enc_payload, mut transport) = hs
        .finish(&device.noise_key.private, &device.noise_key.public, &payload)
        .map_err(|e| format!("finish handshake: {e}"))?;
    let client_finish = waproto::ClientFinish::new(enc_static, enc_payload).encode();
    let mut frame = Vec::new();
    encode_frame(&client_finish, &mut frame).map_err(|e| e.to_string())?;
    ws.send(Message::Binary(frame)).map_err(|e| format!("send ClientFinish: {e}"))?;
    println!("[*] sent registration ClientPayload, waiting for pair-device...\n");

    // 4. Read encrypted stanzas until the pair-device IQ arrives.
    for _ in 0..40 {
        let frame = read_frame(&mut ws, &mut reader)?;
        let plaintext = transport.decrypt(&frame).map_err(|e| format!("transport decrypt: {e}"))?;
        let unpacked = unpack_stanza(&plaintext)?;
        if std::env::var("WAPAIR_DEBUG").is_ok() {
            let hexs: String = unpacked.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("    [debug] stanza {}B: {hexs}", unpacked.len());
        }

        match wabin::unmarshal(&unpacked) {
            Ok(node) => {
                if let Some(refs) = extract_pair_refs(&node) {
                    println!("\n[+] got pair-device with {} ref(s) — showing QR\n", refs.len());
                    show_qr(&refs[0], &device);
                    println!("\n[*] On your phone: WhatsApp → Settings → Linked devices → Link a device,");
                    println!("    then scan the QR above. (Refs rotate; re-run if it expires.)");
                    return Ok(());
                }
                if node.tag == "failure" {
                    let reason = node.get_attr("reason").unwrap_or("?");
                    let detail = match reason {
                        "405" => "client out of date — the advertised WhatsApp-web version is too old",
                        "403" | "401" => "logged out / not authorized",
                        "402" => "temporarily banned",
                        "409" => "user agent rejected",
                        _ => "connection rejected",
                    };
                    return Err(format!(
                        "server <failure reason=\"{reason}\"> ({detail}); location={}",
                        node.get_attr("location").unwrap_or("?")
                    ));
                }
                println!("    parsed <{}> attrs={:?}", node.tag, node.attrs);
            }
            Err(e) => println!("    (could not parse this stanza: {e})"),
        }
    }
    Err("did not receive a pair-device IQ".into())
}

// --------------------------------------------------------------------------------------------

fn load_or_create_device() -> Result<DeviceIdentity, String> {
    if let Ok(json) = fs::read_to_string(SESSION_FILE) {
        if let Ok(d) = DeviceIdentity::from_json(&json) {
            println!("[*] loaded existing device identity from {SESSION_FILE}");
            return Ok(d);
        }
    }
    let d = DeviceIdentity::generate();
    let json = d.to_json().map_err(|e| e.to_string())?;
    fs::write(SESSION_FILE, json).map_err(|e| format!("save session: {e}"))?;
    println!("[*] generated a new device identity -> {SESSION_FILE}");
    Ok(d)
}

fn build_registration_payload(device: &DeviceIdentity) -> Vec<u8> {
    let (p, s, t) = waproto::client_payload::WA_VERSION;
    let version = format!("{p}.{s}.{t}");
    let build_hash: [u8; 16] = Md5::digest(version.as_bytes()).into();
    waproto::RegistrationPayload {
        registration_id: device.registration_id,
        signed_pre_key_id: device.signed_pre_key.key_id,
        identity_public: device.identity_key.public,
        signed_pre_key_public: device.signed_pre_key.key_pair.public,
        signed_pre_key_signature: device.signed_pre_key.signature.clone(),
        build_hash,
        device_os: DEVICE_LABEL.to_string(),
    }
    .encode()
}

/// Strip the WhatsApp stanza framing: a 1-byte flag; if bit 1 (`& 2`) is set, the remainder is
/// zlib-compressed (whatsmeow `waBinary.Unpack`). Returns the raw binary-XMPP node bytes.
fn unpack_stanza(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let (&flag, body) = data.split_first().ok_or("empty stanza")?;
    if flag & 2 != 0 {
        let mut out = Vec::new();
        flate2::read::ZlibDecoder::new(body)
            .read_to_end(&mut out)
            .map_err(|e| format!("zlib inflate: {e}"))?;
        Ok(out)
    } else {
        Ok(body.to_vec())
    }
}

/// Find a `pair-device` IQ and return its `<ref>` values.
fn extract_pair_refs(node: &Node) -> Option<Vec<String>> {
    if node.tag != "iq" {
        return None;
    }
    let pair_device = node.child_nodes().iter().find(|n| n.tag == "pair-device")?;
    let refs: Vec<String> = pair_device
        .child_nodes()
        .iter()
        .filter(|n| n.tag == "ref")
        .filter_map(|n| n.content_bytes().map(|b| String::from_utf8_lossy(b).into_owned()))
        .collect();
    (!refs.is_empty()).then_some(refs)
}

fn show_qr(reference: &str, device: &DeviceIdentity) {
    // Current WhatsApp Web QR: a wa.me linked-devices URL whose fragment is
    // "ref,b64(noisePub),b64(identityPub),b64(advSecret),clientType". clientType 9 = other web client.
    let core = waclient::qr_payload(reference, device);
    let url = format!("https://wa.me/settings/linked_devices#{core},9");
    if qr2term::print_qr(&url).is_err() {
        println!("(could not render QR; raw payload below)");
    }
    println!("\n    QR payload: {url}");
}

// --- websocket helpers ------------------------------------------------------------------------

fn connect() -> Result<WebSocket<MaybeTlsStream<TcpStream>>, String> {
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
    let (ws, _) = tungstenite::connect(request).map_err(|e| format!("ws connect: {e}"))?;
    println!("[*] connected to web.whatsapp.com");
    Ok(ws)
}

fn set_read_timeout(ws: &WebSocket<MaybeTlsStream<TcpStream>>, d: Duration) {
    match ws.get_ref() {
        MaybeTlsStream::Plain(s) => {
            let _ = s.set_read_timeout(Some(d));
        }
        MaybeTlsStream::NativeTls(s) => {
            let _ = s.get_ref().set_read_timeout(Some(d));
        }
        _ => {}
    }
}

/// Read WebSocket messages until one complete length-framed frame is available.
fn read_frame(
    ws: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    reader: &mut FrameReader,
) -> Result<Vec<u8>, String> {
    if let Some(frame) = reader.next_frame() {
        return Ok(frame);
    }
    loop {
        match ws.read().map_err(|e| format!("ws read: {e}"))? {
            Message::Binary(data) => {
                reader.push(&data);
                if let Some(frame) = reader.next_frame() {
                    return Ok(frame);
                }
            }
            Message::Close(c) => return Err(format!("server closed: {c:?}")),
            _ => {}
        }
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64_lite::encode;
    encode(bytes)
}

/// Tiny standard-base64 encoder (avoids adding a base64 dep just for logging).
mod base64_lite {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    pub fn encode(input: &[u8]) -> String {
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 { ALPHABET[((n >> 6) & 63) as usize] as char } else { '=' });
            out.push(if chunk.len() > 2 { ALPHABET[(n & 63) as usize] as char } else { '=' });
        }
        out
    }
}
