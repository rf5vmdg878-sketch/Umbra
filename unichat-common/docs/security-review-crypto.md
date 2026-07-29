# Security review — cryptographic paths

Scope: the crypto and protocol code in `unichat-common/core` — `crypto/*`
(primitives, envelope, key files), `session`, `sync` (offline + mailbox),
`groups`, `share`, and `storage`. Method: manual read for the high-risk bug
classes (nonce/key reuse, weak/mis-bound AEAD, timing side channels,
signature/verification gaps, panic-on-attacker-input DoS, secret leakage,
fail-open behavior, randomness) plus the existing KAT/interop/tamper test suite
(54 tests).

## Verdict

**No memory-safety defects, no cryptographic breaks, and no panic-on-hostile-
input paths were found in the crypto core.** The primitive usage is disciplined
and the constructions are sound. All findings below are **protocol/service-layer
hardening** items (several already documented as limitations), not primitive
misuse.

## What was verified as correct

- **AEAD nonce discipline.** `AeadKey` uses 96-bit counter nonces, never random.
  Every key is single-use per (key, counter): session directional keys +
  per-direction counters; envelope per-file key + per-chunk counter; group and
  offline messages derive a fresh per-message key from a random 32-byte HKDF
  salt and use counter 0. No nonce is reused under any key. Counter overflow is
  a checked error, not a wrap.
- **AAD binding.** Every record binds its context: envelope headers + chunk
  index + final flag; session direction + counter; group/offline messages bind
  the group/recipient id. Reorder, truncation, cross-context splicing, and
  cross-group replay all fail authentication (covered by tests).
- **Fail-closed.** `AeadKey::open` clears the buffer on auth failure — no partial
  or unauthenticated plaintext is ever returned. Decrypt errors propagate.
- **Signatures.** All Ed25519 verification uses `verify_strict` (rejects the
  malleable/small-order edge cases). The session handshake signs the full
  transcript (both identities + both ephemeral keys), giving channel binding
  against MITM/unknown-key-share. Bundles bind the X-Wing key to the identity.
- **Hybrid KEM.** X-Wing (ML-KEM-768 + X25519) is used everywhere a KEM is
  needed — never a single component. Validated against the official draft KATs
  and cross-checked against an independent implementation. Implicit-rejection
  (a wrong ciphertext yields a pseudo-random secret, not an oracle) is intended
  and lands on a downstream AEAD auth failure.
- **Constant-time comparisons.** The share auth MAC compares with `subtle`
  (`ct_eq`); GCM tag checks and Ed25519 verification are constant-time inside
  SymCrypt/dalek. No secret-dependent branching found.
- **KDFs.** HKDF-SHA-256 for key separation; Argon2id for passphrases with a
  parameter floor (≥8 MiB, t≥1, p≥1) enforced at decode and the parameters
  AAD-bound, blocking downgrade tampering. Storage uses a master-key envelope
  so passphrase changes never re-encrypt (or weaken) the body.
- **Randomness.** All keys/nonces/salts/challenges come from SymCrypt's FIPS
  DRBG (`SymCryptRandom`). No `rand`/time-seeded fallback on crypto paths.
- **Secret hygiene.** Secrets live in `Zeroizing`; key types have no derived
  `Debug` (or a redacting one); no logging of key material in the core. The
  MAC is a SHA3 secret-prefix construction, which is safe (SHA3 resists
  length-extension, unlike SHA-2).
- **Parsers.** Network/attacker-facing parsing is length-prefixed and bounded
  (per-message caps), and binary field slicing is guarded by explicit length
  checks before every `try_into().unwrap()`. No reachable panic from crafted
  input was found.

## Findings (protocol/service-layer hardening)

### M1 — Asynchronous messages lack replay/duplication protection · Medium
Offline (`sync`) and group (`groups`) messages are authenticated but carry no
receiver-tracked message id, so a malicious mailbox/relay (or network) can
**re-deliver** a valid message. This is duplication, **not forgery** (content
and author stay authentic). *Fix:* attach a random per-message id and dedup on
the receiver (a bounded seen-set); or a per-author monotonic counter. Session
(Phase 3) is already replay-safe via its monotonic counter.

### M2 — Unauthenticated deposit/post enables quota/resource abuse · Medium
Mailbox `deposit` and group `post` accept from anyone who knows the (public)
owner-id/group-id — content stays sealed and unreadable, but an attacker can
fill an owner's mailbox to its cap or flood a group with ciphertext members must
discard. *Fix:* a deposit token / proof-of-work / rate-limit, or authenticated
deposit for contacts. Already noted as a limitation in the Phase 4/5 notes.

### M3 — Server accept loops are unbounded · Medium (availability)
The mailbox/relay/share `serve` loops spawn a thread per connection with no
cap. A connection flood exhausts threads/memory. *Fix:* a bounded worker pool +
per-IP/connection limits and read timeouts. (Library `handle_connection` is
fine; this is the CLI/host driver.)

### L1 — No forward secrecy for asynchronous messages · Low (by design)
Offline and group messages seal to long-term keys, so a future key compromise
decrypts stored ciphertext. Session chat has per-session FS. *Fix (roadmap):* a
sender-key/prekey ratchet. Documented.

### L2 — Decrypted plaintext intermediates not always zeroized · Low
Decrypted `Vec<u8>` for app/group/offline messages and share content are dropped
normally, not zeroized. Best-effort hygiene; low impact given process isolation.
*Fix:* wrap post-decrypt plaintext in `Zeroizing` where it outlives immediate
use.

### L3 — Relay/mailbox metadata exposure · Low (by design)
Relays learn owner/group ids, sizes, counts, and timing (never content or, for
mailboxes, sender identity). Cwtch-style unlinkable delivery is stronger. Use
the Tor fork so the transport hides network location. Documented.

### I1 — Group/offline message ordering is arrival-based · Informational
No causal ordering; display uses embedded timestamps. Acceptable for the model.

## Recommended next actions

1. Implement **M1** (receiver-side dedup) — cheap, removes a real user-visible
   defect. 2. Add **M3** connection bounds + read timeouts to the server
   drivers. 3. Schedule the async-FS ratchet (L1). M2/L3 depend on the broader
   anti-abuse/unlinkability design and can follow.

None of these block use over a trusted transport (LAN) or the Tor fork; the
cryptographic core is sound.
