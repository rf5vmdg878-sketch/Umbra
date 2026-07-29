# Phase 3 design note — session protocol + transport (Tor build)

Phase 3 delivers Ricochet's feature — direct, mutually authenticated 1:1
messaging with a knock/approve contact flow — generalized to run over any
transport and upgraded to post-quantum cryptography.

## Two builds (fork)

This tree is the **Tor** fork. It has two transports:
- `transport::tcp` — direct TCP (LAN/clearnet, testing); always compiled.
- `transport::tor` — Tor v3 onion-service transport via **arti**, behind the
  `tor` cargo feature (`--features tor`). Heavy dependency; gated so the base
  build and tests stay fast.

The companion `unichat-notor` fork is identical minus the Tor transport. The
session protocol, cryptography, tests, and CLI are shared.

## Session handshake, encrypted channel, knock/approve

Identical to the no-Tor fork — a station-to-station authenticated key exchange
over ephemeral X-Wing (ML-KEM-768 + X25519) with Ed25519 transcript
signatures, directional AES-256-GCM with counter nonces, and a knock/approve
contact flow that binds the peer's signed bundle to the handshake-authenticated
identity. See the shared description in `core/src/session/mod.rs`. Verified over
TCP loopback: 5/5 session tests passing (handshake+chat, knock/approve,
knock/reject, mismatched-bundle rejection, MITM rejection).

## Tor onion-service transport (`core/src/transport/tor.rs`)

The OnionShare/Ricochet transport model, post-quantum inside:

- Each profile publishes a **v3 onion service** (`launch_onion_service`) as its
  address, and dials peers by `<onion>.onion:port` (`TorClient::connect`).
- Tor (arti) provides location anonymity and carrier encryption; the unichat
  session protocol on top provides post-quantum confidentiality and mutual
  Ed25519 authentication — so a malicious or compromised Tor circuit still
  cannot read or impersonate.
- arti is async (tokio); `BlockingStream` bridges arti's async `DataStream` to
  the synchronous `Read`/`Write` the session protocol expects, by driving each
  op on a dedicated tokio runtime. This keeps the whole codebase
  transport-agnostic.
- **Identity binding:** arti manages the onion secret key in a per-profile
  keystore (`state_dir`); the onion address is the *transport locator*, while
  cryptographic identity is the profile's Ed25519 key authenticated in the
  handshake. Deriving the onion key from the profile identity is a future
  refinement.

## CLI

`unichat chat serve --store S --tor` publishes an onion service and prints its
`.onion`; `unichat chat send --store S --to <onion>.onion:9878 --tor …` dials
it. Without `--tor`, the same commands use direct TCP.

## Live-testing caveat

The onion transport code is real and compiles with `--features tor`, but a live
onion connection was **not** exercised in the build environment (no Tor network
bootstrap available). Its handshake/session logic is covered by the shared
loopback tests, which are transport-agnostic; only the arti wiring itself is
un-exercised at runtime.
