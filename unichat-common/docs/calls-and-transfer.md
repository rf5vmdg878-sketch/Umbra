# E2E file transfer + voice/video calls (relay-routed)

This adds two capabilities on top of the Phase-3 secure session, both routed
through the project's own `umbra-relay` so **no third-party media/file service
is involved**, and both end-to-end encrypted so the relay only ever forwards
ciphertext.

## Session-derived call secret

`SecureChannel` now derives an independent **call secret** from the session's
secret keying material: `HKDF-SHA256(ikm, transcript, "unichat-call-secret-v1")`,
exposed via `SecureChannel::call_secret()` (plus `is_initiator()`). Sub-protocols
key themselves from this without touching the session's own message keys.

## E2E file transfer (`core::xfer`)

`send_file` / `recv_file` run over an established `SecureChannel`: offer
`{name, size}` → accept/decline → stream base64 chunks (48 KiB) inside the
channel's authenticated AEAD frames until the final chunk, with a size check on
receipt. Because it rides the session, it is confidential + tamper-evident in
transit, including through a relay. Tested with a 200 KB transfer over loopback
and end-to-end through the call relay.

## E2E media transport (`core::call`)

`SecureMediaChannel` carries real-time audio + video frames:

- Two directional AES-256-GCM keys are derived from the call secret
  (`caller->callee`, `callee->caller`).
- Each frame is sealed independently, SRTP-style: nonce = per-direction sequence
  counter; AAD binds `kind ‖ seq ‖ timestamp`, so frames can't be reordered
  across audio/video, replayed, or reflected. Frames are length-prefixed.
- `MediaKind::{Audio, Video}` demuxes the two streams after decryption.

**Device layer (`unichat-media`):** the real microphone/camera capture and
playback live in the standalone `unichat-media` crate, kept out of the core so
the crypto build stays light. It provides:

- `AudioIo` — real mic capture and speaker playback via `cpal`. Audio is mono
  16-bit PCM framed in ~20 ms blocks (Opus would compress ~10×, but its bindings
  need `cmake`, which isn't on this toolchain; PCM is uncompressed but real).
  A lock-free ring buffer decouples cpal's real-time callback from the call.
- `Camera` — real camera capture via `nokhwa`, encoded to JPEG (MJPEG-style)
  with the pure-Rust `jpeg-encoder`; the far side decodes with `image` to RGBA.
- `run_call(stream, call_secret, is_caller, video, on_video, status)` — a live
  full-duplex call: it splits the handshaked stream, derives the two directional
  media keys (`media_key_pair`), and runs capture→encrypt→send on one thread and
  receive→decrypt→play/display on another. Incoming video frames are delivered
  to `on_video` for the GUI to show; audio plays on the speaker.

The GUI (`umbra`) and the CLI (`unichat call`) both drive real calls through this
by default (the `media` feature, on by default; build with `--no-default-features`
to fall back to the synthetic path). Note: whether you actually *hear* and *see*
the other side can only be validated on a machine with a working mic, camera, and
speaker attached — the code compiles and is API-correct, but headless CI cannot
exercise the hardware.

## Call rendezvous relay (`core::call::relay` + `umbra-relay`)

The relay pairs two callers by a public `call_id` and pumps opaque bytes between
them — it cannot read the call:

1. Each peer dials the relay's call port and sends a rendezvous header
   (`UNICALL1 ‖ call_id ‖ role`) — `call::rendezvous`.
2. The relay (`CallRelay`) matches the two connections by `call_id` and
   bidirectionally forwards bytes until either hangs up.
3. Over that transparent pipe the peers run the **normal PQ session handshake**
   (mutually authenticated, forward-secret), then transfer files / stream media.

`umbra-relay` exposes this as a third service (`call_bind`, default `:9930`)
alongside the group relay and mailbox, with the same access controls (IP
allowlist, connection cap, idle timeout). Calls are live, so there is no spool
persistence for them. Front the bind with a Tor onion service for a private,
location-hidden call relay.

## CLI

`unichat call send-file|recv-file --relay <addr> --id <call-id> …` for E2E file
transfer, and `unichat call dial|answer --relay <addr> --id <call-id> [--video]`
for a live voice/video call using the real mic/camera (`unichat-media`). Both
sides agree on `--id` out of band (e.g. via a `CallOffer` chat message).

## Tests (`core/tests/call_xfer.rs`, 5/5)

Audio+video frame round-trip; wrong-key rejection; 200 KB file transfer over a
session; relay byte-forwarding both directions; and the full end-to-end path —
two peers meet on the relay, complete the PQ handshake, transfer a file, and
exchange encrypted audio+video, with the peer authenticated and the relay unable
to read any of it.
