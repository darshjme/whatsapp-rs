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
use wanoise::noise::{NoiseTransport, XxInitiator};

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

    // 4. Pairing loop: render the QR on pair-device; on pair-success sign the device identity,
    //    send pair-device-sign, and finish on <success>.
    let mut shown_hint = false;
    for _ in 0..200 {
        let frame = read_frame(&mut ws, &mut reader)?;
        let plaintext = transport.decrypt(&frame).map_err(|e| format!("transport decrypt: {e}"))?;
        let unpacked = unpack_stanza(&plaintext)?;
        if std::env::var("WAPAIR_DEBUG").is_ok() {
            let hexs: String = unpacked.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("    [debug] stanza {}B: {hexs}", unpacked.len());
        }
        let node = match wabin::unmarshal(&unpacked) {
            Ok(n) => n,
            Err(e) => {
                println!("    (unparsable stanza: {e})");
                continue;
            }
        };

        match node.tag.as_str() {
            "failure" => {
                let reason = node.get_attr("reason").unwrap_or("?");
                let detail = match reason {
                    "405" => "client out of date - advertised WhatsApp version too old",
                    "403" | "401" => "logged out / not authorized",
                    "402" => "temporarily banned",
                    "409" => "user agent rejected",
                    _ => "connection rejected",
                };
                return Err(format!("server <failure reason=\"{reason}\"> ({detail})"));
            }
            "success" => {
                println!("\n*** PAIRED *** this device is now linked to the account.");
                return Ok(());
            }
            "iq" => {
                let id = node.get_attr("id").unwrap_or("").to_string();
                let from = node.get_attr("from").unwrap_or("s.whatsapp.net").to_string();
                if let Some(pd) = node.child_nodes().iter().find(|n| n.tag == "pair-device") {
                    send_node(&mut ws, &mut transport, &ack_iq(&from, &id))?;
                    let refs: Vec<String> = pd
                        .child_nodes()
                        .iter()
                        .filter(|n| n.tag == "ref")
                        .filter_map(|n| n.content_bytes().map(|b| String::from_utf8_lossy(b).into_owned()))
                        .collect();
                    if let Some(r) = refs.first() {
                        println!("\n[+] pair-device ({} ref(s)) - scan this QR:\n", refs.len());
                        show_qr(r, &device);
                        if !shown_hint {
                            println!("\n[*] On your phone: WhatsApp -> Linked devices -> Link a device -> scan.");
                            println!("    Use a SECONDARY/burner number. The QR refreshes until you scan.");
                            shown_hint = true;
                        }
                    }
                } else if let Some(ps) = node.child_nodes().iter().find(|n| n.tag == "pair-success") {
                    println!("\n[+] phone authorized the link - signing device identity...");
                    let di = ps
                        .child_nodes()
                        .iter()
                        .find(|n| n.tag == "device-identity")
                        .and_then(|n| n.content_bytes())
                        .ok_or("pair-success missing <device-identity>")?;
                    let result = waclient::complete_pair_success(di, &device)
                        .map_err(|e| format!("pair-success: {e}"))?;
                    let jid = ps
                        .child_nodes()
                        .iter()
                        .find(|n| n.tag == "device")
                        .and_then(|n| n.get_attr("jid"))
                        .unwrap_or("?")
                        .to_string();
                    send_node(
                        &mut ws,
                        &mut transport,
                        &pair_device_sign(&id, result.key_index, &result.self_signed_identity),
                    )?;
                    println!("[+] sent pair-device-sign; finalizing as {jid} ...");
                }
            }
            other => println!("    (stanza <{other}>)"),
        }
    }
    Err("pairing did not complete in time".into())
}

/// Wrap stanza node bytes with the 1-byte uncompressed flag (the inverse of unpack_stanza).
fn pack_stanza(node_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + node_bytes.len());
    out.push(0); // flag: no zlib compression
    out.extend_from_slice(node_bytes);
    out
}

/// Marshal, pack, transport-encrypt and frame a stanza, then send it.
fn send_node(
    ws: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    transport: &mut NoiseTransport,
    node: &Node,
) -> Result<(), String> {
    let node_bytes = wabin::marshal(node).map_err(|e| format!("marshal: {e}"))?;
    let ct = transport
        .encrypt(&pack_stanza(&node_bytes))
        .map_err(|e| format!("encrypt: {e}"))?;
    let mut frame = Vec::new();
    encode_frame(&ct, &mut frame).map_err(|e| format!("frame: {e}"))?;
    ws.send(Message::Binary(frame)).map_err(|e| format!("ws send: {e}"))
}

/// `<iq to=.. id=.. type="result"/>` — the ack for a `pair-device` IQ.
fn ack_iq(to: &str, id: &str) -> Node {
    Node::new("iq").attr("to", to).attr("id", id).attr("type", "result")
}

/// `<iq to="s.whatsapp.net" type="result" id=..><pair-device-sign><device-identity key-index=..>
/// {self-signed identity}</device-identity></pair-device-sign></iq>`.
fn pair_device_sign(id: &str, key_index: u32, self_signed: &[u8]) -> Node {
    Node::new("iq")
        .attr("to", "s.whatsapp.net")
        .attr("type", "result")
        .attr("id", id)
        .children(vec![Node::new("pair-device-sign").children(vec![Node::new("device-identity")
            .attr("key-index", key_index.to_string())
            .bytes(self_signed.to_vec())])])
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
    // Version + platform are overridable for fast iteration once we know the current accepted value:
    //   WAPAIR_VERSION=2.3000.1234567890  WAPAIR_PLATFORM=14  cargo run -p wapair
    let app_version = std::env::var("WAPAIR_VERSION")
        .ok()
        .and_then(|s| parse_version(&s))
        .unwrap_or(waproto::client_payload::WA_VERSION);
    let platform = std::env::var("WAPAIR_PLATFORM")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(waproto::client_payload::WA_PLATFORM);

    let (p, s, t) = app_version;
    let version = format!("{p}.{s}.{t}");
    let build_hash: [u8; 16] = Md5::digest(version.as_bytes()).into();
    println!("[*] advertising version {version}, platform {platform}");
    waproto::RegistrationPayload {
        registration_id: device.registration_id,
        signed_pre_key_id: device.signed_pre_key.key_id,
        identity_public: device.identity_key.public,
        signed_pre_key_public: device.signed_pre_key.key_pair.public,
        signed_pre_key_signature: device.signed_pre_key.signature.clone(),
        build_hash,
        device_os: DEVICE_LABEL.to_string(),
        app_version,
        platform,
    }
    .encode()
}

/// Parse "2.3000.1041871181" into a version tuple.
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let p: Vec<u64> = s.split('.').filter_map(|x| x.parse().ok()).collect();
    match p.as_slice() {
        [a, b, c, ..] => Some((*a, *b, *c)),
        _ => None,
    }
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
