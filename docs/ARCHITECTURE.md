# Architecture & Protocol Map

This document captures the protocol `whatsapp-rs` implements, reverse-engineered from the official
**WhatsApp for Windows `2.2623.103.0`** (native .NET 8 + WinUI 3, with C++/Rust native cores). It is the
design source-of-truth; the corresponding knowledge base lives in the author's vault as
*"WhatsApp Official App — Protocol Teardown (KB)"*.

## The four layers

```
┌─────────────────────────────────────────────────────────────┐
│  waagent   chatbot + voice agent (STT → LLM → TTS, barge-in) │
├─────────────────────────────────────────────────────────────┤
│  waclient  session · QR pairing · send/recv · app-state sync │
│  wavoip    call signalling · ICE/STUN/TURN · SRTP · Opus     │
├──────────────────────────┬──────────────────────────────────┤
│  wasignal  E2E (Signal)  │  waproto  protobuf message schemas│
├──────────────────────────┴──────────────────────────────────┤
│  wanoise   Noise_XX handshake + length-framed transport      │
├─────────────────────────────────────────────────────────────┤
│  wabin     binary-XMPP node (stanza) codec   ← implemented   │
└─────────────────────────────────────────────────────────────┘
              socket → g.whatsapp.net (chatd gateway)
```

### 1. Transport — `wanoise`
- TLS-less; security comes from a **Noise Protocol `Noise_XX`** handshake to **`g.whatsapp.net`**
  (fallback `g-fallback.whatsapp.net`).
- After the handshake, traffic is **length-framed** binary (`FramesReader`/`FramesWriter`,
  `FrameHeaderSize`, `ProcessFrame` in the official client).
- Optional QUIC path via `msquic`.

### 2. Wire codec — `wabin` ✅
- Token-compressed binary XMPP **nodes** (stanzas). Implemented here: list sizing
  (`LIST_EMPTY/8/16`), string tokens, `NIBBLE_8`/`HEX_8` packing, `JID_PAIR`/`AD_JID`,
  `BINARY_8/20/32` blobs, nested children. Round-trip tested.
- TODO: import the full canonical single-byte + 3× double-byte token dictionaries for live interop.

### 3. Crypto — `wasignal` + `waproto`
- **Signal protocol**: identity keys, signed prekeys + one-time prekeys (`PreKeys.Set`), per-session
  `SessionCipher`, **SenderKeys** for groups (`SenderKeyDistributionMessage`).
- **Companion device** model: this client is a *linked device*, paired by QR. Pairing identity =
  `ADVSignedDeviceIdentity` + `HandshakeMessage` + `ClientPayload` protobufs, signed by the phone.
- Addressing: `<user>@s.whatsapp.net`, groups `@g.us`, and the opaque `@lid` mode handled by an
  `AddressingModeParser` (PN ↔ LID).

### 4. RPC surface ("Smax")
The official client generates typed request/response handlers over stanzas. Observed categories:
**Groups** (get/batch-get info, participating groups, invite-link join, membership approvals,
set-property), **PreKeys** (set), **Blocklists** (get/update), **Bot** (bot list — the AI registry),
**Tos** (acceptance), **Offline/ThreadMetadata** (history sync), **DirtyBits** (server re-sync signals).
Media is a Signal-encrypted blob to **`mmg.whatsapp.net`**; only key + pointer travel in the stanza.

## Voice calling — `wavoip` (the hard part) 🔬
The official engine is the cross-platform `wa-voip` core:
- **Signalling**: call **stanzas** over the same chatd channel, driven by a Rust `call_control` crate
  (`signaling_xml`, `stanza_deserializer`, `shared_elements::{encryption, transport}`). Verbs:
  `call_accept` (offer/accept/terminate/transport), offer buffering + peek timeouts.
- **Transport**: ICE/STUN/TURN, **SRTP/DTLS** encrypted media, bandwidth probing
  (`BANDWIDTH_MANAGED`), built atop **PJSIP/pjproject**.
- **Audio DSP**: full WebRTC pipeline — **AEC3** echo cancel, **AGC2** gain, **NS** noise suppression;
  **Opus** codec. Video: VP8/VP9/**AV1**, H.264/265.
- Keys derive from the Signal session, so call media is genuinely end-to-end encrypted.

## The AI agent loop — `waagent`
The official client already ships a **GenAI voice agent** path we mirror:
`wa_live_transcription_controller_on_rx` (live STT on the inbound stream) + Genai* telemetry
(`GenaiBotEarlyConnectVoipLatencyMs`, `GenaiInitialTranscriptionLatencyMs`,
`GenaiInterruptDuckingLatencyMs`). The loop:

```
call connect → live STT (inbound audio) → LLM → TTS (outbound audio)
                         ↑__________ barge-in / ducking __________↓
```

For a production, ToS-clean deployment, `waagent` will also support bridging via the official
**WhatsApp Business Calling API** as an alternative to the native `wavoip` plane.

## Build order
1. `wabin` ✅ → 2. `wanoise` (handshake, get bytes flowing) → 3. `waproto` + `wasignal` (decrypt/encrypt)
→ 4. `waclient` (QR pair, first message send/recv) → 5. `wavoip` (call signalling, then media) →
6. `waagent` (chatbot first, then voice).
