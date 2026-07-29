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

**Device/codec seam (not yet wired):** actual microphone/camera capture and
Opus/VP8 encode+decode plug into the `MediaSource` / `MediaSink` traits. This
crate carries and protects whatever bytes they produce; it does not itself touch
hardware or run codecs. That integration (e.g. `cpal` + `opus` for audio, a
camera crate + a video codec for video) needs a machine with real devices to
build and verify, and is the remaining work to make it a "pick up and hear/see"
product. The cryptographic media transport is complete and tested with synthetic
frames.

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
for a voice/video call (synthetic media until the device layer is wired). Both
sides agree on `--id` out of band (e.g. via a `CallOffer` chat message).

## Tests (`core/tests/call_xfer.rs`, 5/5)

Audio+video frame round-trip; wrong-key rejection; 200 KB file transfer over a
session; relay byte-forwarding both directions; and the full end-to-end path —
two peers meet on the relay, complete the PQ handshake, transfer a file, and
exchange encrypted audio+video, with the peer authenticated and the relay unable
to read any of it.
