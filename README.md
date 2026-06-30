# whatsapp-rs

> A native **Rust** implementation of the WhatsApp **multi-device** protocol — text **and** voice —
> built from a ground-up study of the official client, not wrapped around an existing library.

WhatsApp's desktop/mobile apps talk to Meta's servers over a custom stack: a **Noise** handshake, a
**binary XMPP** stanza stream, the **Signal** protocol for end-to-end encryption, and the **`wa-voip`**
media engine for calls. The existing open-source ecosystem (whatsmeow in Go, Baileys in JS) reimplements
the messaging half — but **none implement the voice-call media plane**. `whatsapp-rs` aims to do both, in
one cohesive Rust workspace, and to expose a clean agent layer so you can build an **AI chatbot and an
AI voice-calling agent** that pair with a **single QR scan**.

This mirrors how the official client is actually built — its own security and media cores are Rust
(`xplat/wa-voip/rust/call_control`, `WhatsAppRust.dll`).

## Why
- **Voice is the gap.** Real, end-to-end-encrypted WhatsApp call audio (Opus over SRTP) has no FOSS
  implementation. That's the frontier this project targets.
- **Rust everywhere.** One language for the wire codec, the crypto, the SRTP/Opus media plane, and the
  agent runtime — memory-safe, fast enough for real-time audio.
- **Agent-first.** The end goal is a batteries-included WhatsApp AI: inbound message → LLM → reply, and
  inbound/outbound **call → live STT → LLM → TTS → barge-in**, the same loop Meta ships for Meta AI calls.

## Workspace layout (planned)
| crate | responsibility | status |
|-------|----------------|--------|
| **`wabin`** | binary-XMPP node codec (the wire format) | ✅ implemented + tested |
| `wanoise` | Noise `XX` handshake + framed transport to `g.whatsapp.net` | 🔜 |
| `wasignal` | Signal protocol: identities, prekeys, sessions, sender keys | 🔜 |
| `waproto` | protobuf message schemas (`Message`, `WebMessageInfo`, `ClientPayload`, …) | 🔜 |
| `waclient` | session, QR pairing (companion device), send/receive, app-state sync | 🔜 |
| `wavoip` | `wa-voip` media plane: call signalling stanzas, ICE/SRTP, Opus | 🔬 research |
| `waagent` | chatbot + voice-agent runtime (STT → LLM → TTS, barge-in/ducking) | 🔜 |

## Status
Early. The foundational wire codec (`wabin`) is done and round-trip tested. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the protocol map this is built from.

```bash
cargo test -p wabin
```

## Legal & safety
For interoperability research and building automation **on accounts you control**. Respect WhatsApp's
Terms of Service. Use a secondary number while developing, and warm new numbers up gradually — cold
numbers that send volume fast get banned.

## License
Dual-licensed under **MIT OR Apache-2.0**.
