# Phase 5 design note — untrusted-relay groups

Phase 5 delivers Cwtch's group-messaging feature: group chat where the relay
(server) is **untrusted** — it stores and forwards sealed blobs it cannot read,
does not know who authored them, and enforces no membership. Privacy comes from
the shared group key, not from the server.

## Group identity (`groups::Group`)

A group is a public **16-byte group id** (its relay address) plus a secret
**32-byte group key**. `Group::create` generates both randomly. The
**descriptor** (`unichat-group-v1:<base64>` = name ‖ id ‖ key) is the invite:
anyone given it becomes a member, so it must travel only over a secure channel
(a Phase 3 session or a Phase 4 sealed message). Joined groups are persisted in
the encrypted profile (`Profile.groups`, `#[serde(default)]` for
back-compat) — the group key sits there only because the whole profile DB is
encrypted at rest, and it is zeroized on drop.

## Per-message crypto (`group_seal` / `group_open`)

Many members share one key, so a **per-message key** is derived from a fresh
random 32-byte salt: `msg_key = HKDF-SHA256(group_key, salt,
"unichat-group-msg-v1")`, then AES-256-GCM with a zero nonce. Each `msg_key` is
unique, so nonce reuse is impossible — this deliberately avoids GCM's 96-bit
random-nonce birthday bound with many concurrent writers (the reason a naive
"random nonce under a shared key" scheme is unsafe at scale).

The plaintext carries the author's Ed25519 identity and a signature over
`SHA3-256(domain ‖ group_id ‖ inner)`, all *inside* the ciphertext. So every
member cryptographically verifies **who** wrote each message and that it belongs
to **this** group; the group id is also the AEAD associated data. A blob from
one group cannot be decrypted, nor replayed, into another.

## Untrusted relay (`groups::relay`)

Cwtch's "dumb server": a map from group id to an append-only list of blobs.
- **Post** (any member): appends a blob; bounded by `MAX_MSGS_PER_GROUP` /
  `MAX_BLOB_SIZE`.
- **Fetch** (anyone with the group id): returns blobs after a cursor
  (server-assigned index) and the new cursor, so clients pull only new messages.
- The relay never sees plaintext or authorship, and different groups are fully
  isolated address spaces. It runs over any `transport` (LAN TCP or a Tor onion
  service).

## CLI

`group create|join|list|leave`, `group post|fetch`, and `relay serve` (Tor fork
adds `--tor` to publish/reach the relay as an onion service). Fetched messages
show the author as a contact alias when known, `me` for your own, or
`member#<fp>` for an authenticated-but-unknown member.

## Tests (`core/tests/groups.rs`, 8/8)

Descriptor round-trip; authenticated seal/open; non-member cannot read; tampered
message rejected; cross-group replay rejected; a 3-member relay round-trip with
cursor-based incremental fetch; relay blindness + group isolation (the stored
ciphertext never contains the plaintext; a second group sees nothing); and
profile group persistence.

## Limitations / future work

- **No forward secrecy / removal:** the group key is long-lived; "removing" a
  member requires rotating to a new group (new key + descriptor). A group
  key-ratchet / member-set protocol is future work.
- **Relay linkability & spam:** the relay sees a group id plus post timing and
  counts, and posts are unauthenticated (bounded only by size/count). Cwtch's
  fuller server design adds unlinkability and anti-spam; both are future phases.
- **Ordering** is by relay arrival (the fetch cursor); messages also carry a
  timestamp for display. No global causal ordering yet.
