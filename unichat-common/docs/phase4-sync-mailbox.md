# Phase 4 design note — store-and-forward sync + untrusted mailbox

Phase 4 delivers Briar's offline-delivery feature: messaging when the two peers
are **never online at the same time**, via an untrusted store-and-forward node.
It builds on the Phase 1 envelope and the Phase 2 identity/contact model, and
runs over the Phase 3 transport abstraction (so it works on LAN/TCP or over Tor
onion services unchanged).

## Offline sealed messages (`sync::seal_message` / `open_message`)

- A message is sealed to the recipient's **long-term X-Wing key** (from their
  contact bundle) with the Phase 1 `.usealed` envelope — post-quantum
  confidential and integrity-protected, openable later with no live handshake.
- Because there is no session to authenticate the sender, the sender also
  **signs** `SHA3-256(domain ‖ recipient_id ‖ envelope)` with its Ed25519
  identity key and attaches its identity. `open_message` verifies the signature,
  decrypts, and returns the authenticated sender id; the caller confirms the
  sender is a known contact.
- Result: offline messages are confidential to the recipient, tamper-evident,
  and sender-authenticated — the same guarantees as a live session, minus
  forward secrecy (the trade-off inherent to asynchronous delivery; noted below).

## Untrusted mailbox (`sync::mailbox`)

Briar's mailbox model, post-quantum inside:

- Addressed by the **owner's Ed25519 identity public key**. The mailbox knows
  its owner but nothing else.
- **Deposit** (any sender, anonymous): stores an opaque sealed blob. Bounded by
  `MAX_BLOB_SIZE` and `MAX_BLOBS_PER_OWNER` against spam/exhaustion.
- **Collect** (owner only): a challenge-response — the server issues a random
  nonce, the collector signs it with the owner's identity key, the server
  verifies against the owner-id public key before releasing (and clearing) the
  blobs. The per-connection nonce prevents replay.
- The mailbox **cannot read** blobs (sealed to the owner's X-Wing key) and never
  learns sender identities. It runs over any `transport` — a LAN TCP node or a
  Tor onion service.

Wire protocol: `u32-le length ‖ JSON` frames — `Deposit` → `Ok`; `ChallengeReq`
→ `Challenge{nonce}` → `Collect{sig}` → `Blobs`.

## CLI

- `unichat mailbox serve --bind ADDR` (Tor fork: `--tor` publishes an onion
  service).
- `unichat msg send --store S --to ALIAS --via ADDR --message TEXT`.
- `unichat msg collect --store S --via ADDR`.

## Tests (`core/tests/sync_mailbox.rs`, 6/6)

Authenticated seal/open round-trip; wrong recipient cannot open; tampered blob
rejected; full store-and-forward over TCP (deposit while offline → collect →
decrypt, mailbox cleared); only the owner can collect (an impostor gets their
own empty mailbox, the owner's blobs untouched); and the stored blob never
contains the plaintext (mailbox blindness).

## Limitations / future work

- **No forward secrecy** for offline messages (asynchronous delivery seals to a
  long-term key). A sender-key/prekey ratchet (Signal-style) would restore it;
  the sealing layer is isolated so it can be swapped.
- **Mailbox linkability:** the mailbox sees an owner id plus deposit timing and
  counts. Cwtch-style unlinkable group delivery is a stronger model for a later
  phase. Deposits are unauthenticated (rate/size-bounded only) — a proof-of-work
  or token could harden against spam.
- **No sender outbox persistence yet:** a failed deposit isn't queued for retry
  across restarts; that belongs with the Phase 5+ delivery manager.
