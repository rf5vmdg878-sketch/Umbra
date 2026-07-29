# Unified Secure Communications Suite — Build Specification

**Instructions for Claude: synthesize the best features of the source projects in
`_sub_src/` into one coherent, secure application.**

This document is the authoritative design brief. Read it fully before writing code.
Every feature below is traceable to real source code in `_sub_src/` — study the
referenced implementation before re-implementing an idea, and prefer porting proven
logic over inventing new logic.

---

## 1. Source inventory and what to take from each

### 1.1 `_sub_src/cwtch` — Cwtch (Go)
Metadata-resistant messenger from Open Privacy. Key directories: `protocol/`
(Tapir/connections), `model/` (conversations, groups), `peer/` (identity + contact
engine), `event/` (event bus), `storage/`, `settings/`.

**Take:**
- **Metadata resistance as a design axiom** — no central server, no plaintext
  metadata at rest, contacts are onion addresses, servers (when used for offline
  group delivery) are untrusted "dumb" mailboxes that cannot read or correlate.
- **Event-bus architecture** (`event/`): every subsystem (network, storage, UI)
  communicates through typed events on a bus. This cleanly decouples transport
  from application logic and is the backbone we will replicate.
- **Untrusted-infrastructure group messaging** (`model/`, `protocol/`): groups are
  built on peer-to-peer key material; any relay sees only ciphertext blobs.
- **Profile encryption at rest** (`storage/`): each local profile is encrypted
  under a password-derived key.

### 1.2 `_sub_src/briar` — Briar (Java/Kotlin)
P2P messenger with offline-first sync. Key modules: `bramble-core` (Bramble
transport-agnostic sync protocol, crypto, transport plugins), `bramble-api`,
`briar-core` (messaging, forums, blogs), `briar-mailbox` (offline delivery),
`briar-headless` (REST API daemon).

**Take:**
- **Transport-agnostic sync protocol (Bramble)** (`bramble-core/src/main/java/org/briarproject/bramble/sync/`):
  messages are synced opportunistically over *any* available transport — Tor,
  local Wi-Fi, Bluetooth, even USB sticks. The abstraction to copy: a `Transport
  Plugin` interface + a store-and-forward sync layer with per-contact message
  queues and rotating transport keys.
- **Offline/mesh operation**: the app must remain useful with no internet
  (LAN sync), degrading gracefully instead of failing.
- **Mailbox pattern** (`briar-mailbox/`): an optional, self-hosted, *untrusted*
  store-and-forward node for asynchronous delivery when both peers are rarely
  online simultaneously.
- **Headless core + thin UI** (`briar-headless/`): core logic exposed over a
  local authenticated API so multiple UIs (CLI, desktop, mobile) share one engine.

### 1.3 `_sub_src/ricochet-refresh` — Ricochet Refresh (C++)
Direct Tor-onion-service-to-onion-service instant messaging. Key dirs:
`src/libtego/` (protocol core, C API), `src/tego-ui/`, `design/`, `doc/`.

**Take:**
- **Identity = onion service** (`src/libtego/`): your address *is* your v3 onion
  address. No accounts, no registration, no DNS, no phone number. Authentication
  falls out of Tor's onion-service cryptography (ed25519).
- **Contact request protocol** (`doc/`, `design/`): explicit knock/approve flow
  before any channel opens — no unsolicited data from strangers.
- **Library/UI split** (`libtego` C API): protocol engine as an embeddable
  library with a hard API boundary — mirrors Briar's headless lesson; we adopt it.

### 1.4 `_sub_src/onionshare` — OnionShare (Python)
Anonymous file sharing / hosting / chat over ephemeral onion services. Key dirs:
`cli/onionshare_cli/` (core: `onion.py`, `web/`, `settings.py`), `desktop/`.

**Take:**
- **Ephemeral onion services per task** (`cli/onionshare_cli/onion.py`): spin up
  a short-lived v3 onion service for a single share/receive session, then destroy
  it. Nothing persists unless the user opts in.
- **Client authorization for private shares**: onion service client-auth keys so
  only the intended recipient can even *connect*.
- **Receive mode / anonymous dropbox** (`cli/onionshare_cli/web/receive_mode.py`):
  journalist-style upload endpoint with rate limits and no execution of received
  content.
- **UX for one-shot secure actions**: auto-stop after first download, human-
  friendly share flow. Security tooling only works if it is this easy.

### 1.5 `_sub_src/pqspread` — PQSpread (JS/Zenroom)
Serverless post-quantum file encryption in a single offline HTML file
(ML-KEM + AES-GCM, keys in browser storage). Key dirs: `src/`, `contracts/`
(Zenroom crypto contracts), `index.html`.

**Take:**
- **Post-quantum file encryption workflow** (`contracts/`): KEM-encapsulate to a
  recipient public key → AEAD-encrypt the file → ship a self-contained `.pqs`-style
  envelope. We upgrade their ML-KEM-512 to the hybrid X-Wing (ML-KEM-768 + X25519).
- **Zero-infrastructure escape hatch**: an offline, single-artifact encrypt/decrypt
  utility that works when the full app (or Tor) is unavailable — sneakernet-
  compatible, matching Briar's USB transport.
- **Fix their documented weakness**: preserve (encrypt) the original filename
  inside the envelope; PQSpread drops it.

### 1.6 Crypto primitives — Microsoft SymCrypt (primary) + RustCrypto (validation / Argon2id)

**Directive (2026-07-28): the implementation uses Microsoft's SymCrypt** —
`_sub_src/symcrypt` (the FIPS-validated C library that ships in Windows;
prebuilt release DLL vendored at `unichat/vendor/symcrypt/`) with Microsoft's
official Rust bindings `_sub_src/rust-symcrypt` (`symcrypt` crate). SymCrypt
provides ML-KEM-768 (FIPS 203), X25519, AES-256-GCM, SHA3/SHAKE, HKDF and the
DRBG. ML-KEM is reached via a thin FFI layer (`unichat/core/src/crypto/ffi.rs`)
because the published bindings predate it. Argon2id is not in SymCrypt and
comes from the audited RustCrypto `argon2` crate. The RustCrypto `x-wing`
crate remains a **test-only** dev-dependency for cross-vendor validation.

The RustCrypto source clones below stay in `_sub_src/` as reference and
validation material:
- **`rustcrypto-KEMs/x-wing/`** — X-Wing: the standardized hybrid KEM combining
  **ML-KEM-768 + X25519** (draft-connolly-cfrg-xwing-kem). This is the *only* KEM
  the unified app uses. Never ML-KEM alone, never X25519 alone: the hybrid stays
  secure if either component falls.
- **`rustcrypto-KEMs/ml-kem/`** — underlying FIPS-203 ML-KEM implementation.
- **`rustcrypto-AEADs/aes-gcm/`** — **AES-256-GCM** AEAD for all symmetric
  encryption (messages, files, storage blobs).
- **`rustcrypto-password-hashes/argon2/`** — **Argon2id** for every
  password/passphrase-derived key (profile unlock, exported backups).

**Take:** use these as dependencies (pinned crates), not as code to copy. Do not
re-implement any primitive.

---

## 2. The unified application

**Working name:** `unichat` (rename freely). **Core language:** Rust (matches the
crypto crates, memory-safe, embeds everywhere). **Architecture:** one headless
core engine + thin clients, à la `libtego`/`briar-headless`.

### 2.1 Feature synthesis matrix

| Capability | Source of the idea | Unified design |
|---|---|---|
| Identity & addressing | ricochet-refresh | v3 onion address = identity; ed25519 onion key is the root of trust |
| Contact handshake | ricochet-refresh | knock → approve → then (and only then) run key agreement |
| Session key agreement | rustcrypto-KEMs | X-Wing (ML-KEM-768 + X25519) encapsulation during contact handshake; rekey per session |
| Message/file encryption | rustcrypto-AEADs, pqspread | AES-256-GCM under X-Wing-derived keys; self-contained envelopes |
| Metadata resistance | cwtch | P2P first; relays see only sealed blobs; no plaintext metadata at rest |
| Multi-transport sync | briar | Transport-plugin trait: Tor (primary), LAN, removable media; opportunistic store-and-forward |
| Offline delivery | briar-mailbox, cwtch servers | optional self-hosted untrusted mailbox holding only sealed envelopes |
| Group messaging | cwtch | peer-derived group keys; any relay is untrusted |
| File sharing | onionshare | ephemeral per-share onion service + client-auth; auto-stop; receive mode |
| Offline utility | pqspread | standalone `unichat-seal` file encrypt/decrypt tool (same envelope format) |
| At-rest protection | cwtch storage, password-hashes | Argon2id(passphrase) → AES-256-GCM-encrypted profile database |
| Engine/UI split | briar-headless, libtego | `unichat-core` library + local authenticated RPC; CLI first, GUI later |

### 2.2 Cryptographic construction (normative)

1. **Long-term identity:** ed25519 (the onion service key). A separate long-term
   **X-Wing keypair** is generated per profile and signed by the identity key;
   the public half is exchanged during contact approval.
2. **Session establishment:** initiator runs X-Wing `encapsulate()` against the
   peer's X-Wing public key → 32-byte shared secret. Derive directional keys with
   HKDF-SHA-256: `k_send, k_recv = HKDF(ss, salt = transcript_hash, info =
   "unichat-v1" || role)`. The transcript hash binds both identities and both
   public keys (channel binding — prevents unknown-key-share).
3. **Record encryption:** AES-256-GCM. **Nonces are a 96-bit counter per
   direction, never random, never reused**; rekey via fresh encapsulation before
   counter exhaustion and at every new session. AAD carries the envelope header
   (version, sender, sequence number) so headers are integrity-bound.
4. **File envelope (`.usealed`)**, shared by messenger and the offline tool:
   `header {version, X-Wing ciphertext, HKDF salt} || AES-256-GCM(chunks)` with
   the original filename + MIME type encrypted *inside* the payload (fixes
   PQSpread's filename leak). Chunked (1 MiB) so large files stream without
   loading into memory; each chunk's AAD includes the chunk index and a
   final-chunk flag (prevents reorder/truncation).
5. **At-rest storage:** profile DB key = Argon2id(passphrase) with per-profile
   random 16-byte salt and parameters at least `m=64 MiB, t=3, p=4` (tune upward
   to ~500 ms on target hardware; parameters stored alongside the salt for
   forward migration). The derived key wraps a random 256-bit master key
   (envelope pattern → passphrase changes don't re-encrypt the DB).
6. **Forward secrecy / post-compromise security:** per-session re-encapsulation
   gives coarse forward secrecy at v1; a double-ratchet-style layer over X-Wing
   is the v2 roadmap item — design the session module so a ratchet can slot in.

### 2.3 Component layout

```
unichat/
├── core/                 # unichat-core: engine library (Rust)
│   ├── crypto/           # thin wrappers over x-wing, aes-gcm, argon2 ONLY
│   ├── identity/         # onion identity, X-Wing keys, contact store
│   ├── transport/        # Transport trait + tor/, lan/, media/ plugins (Briar model)
│   ├── sync/             # store-and-forward queues, sealed envelopes (Bramble model)
│   ├── groups/           # untrusted-relay groups (Cwtch model)
│   ├── share/            # ephemeral onion file shares (OnionShare model)
│   ├── storage/          # Argon2id-unlocked encrypted profile DB (Cwtch model)
│   └── bus/              # typed event bus (Cwtch model)
├── cli/                  # first client, drives core over local RPC
├── seal/                 # unichat-seal: standalone offline encrypt tool (PQSpread model)
└── docs/                 # threat model, protocol spec, this file's descendants
```

---

## 3. Security requirements (non-negotiable)

1. **Never implement cryptographic primitives.** Only the pinned crates:
   `x-wing`, `ml-kem` (transitively), `aes-gcm`, `argon2`, `hkdf`, `sha2`,
   `ed25519-dalek`, plus `arti-client` (Rust Tor) for transport. Pin exact
   versions; commit `Cargo.lock`; enable `cargo audit`/`cargo deny` in CI.
2. **Hybrid always.** Any code path that would use ML-KEM or X25519 alone is a
   defect.
3. **AEAD discipline.** Counter nonces, AAD-bound headers, rekey thresholds
   enforced in one place (`core/crypto/`), unit-tested against reuse.
4. **Zeroization.** All secret key material in `Zeroizing<>`/`zeroize`-derived
   types; secrets never in `Debug` impls, logs, error messages, or panics.
5. **No plaintext metadata at rest.** Contact lists, message times, filenames —
   everything lives inside the encrypted profile DB. Log files off by default;
   when enabled, log events not contents (follow Cwtch's discipline).
6. **Network hygiene.** All remote traffic through Tor by default (arti). LAN
   transport is opt-in and clearly labeled as location-revealing to local
   observers. No clearnet fallback, ever, without an explicit per-profile toggle.
7. **Untrusted infrastructure.** Mailboxes/relays must be able to prove nothing:
   they store opaque, padded, sealed blobs addressed by rotating pseudonymous
   tags (Briar's rotating transport keys pattern).
8. **Stranger data is hostile.** Ricochet's rule: nothing is parsed from a peer
   before contact approval beyond the fixed-size knock. Received files are never
   auto-opened/executed; receive-mode uploads are size-capped and rate-limited
   (OnionShare's rules).
9. **Constant-time comparisons** for every MAC/tag/key check (`subtle` crate).
10. **Fail closed.** Tor not bootstrapped → offline mode, not clearnet. Decrypt
    error → drop message, surface a tamper warning, never render partial
    plaintext.
11. **Testing bar:** interop test vectors for the envelope format, nonce-reuse
    regression tests, fuzzing (`cargo fuzz`) on every parser (envelope header,
    knock packet, sync frames), and a documented threat model in `docs/` before
    the first release.

---

## 4. Implementation plan for Claude — ALL PHASES COMPLETE ✅

Implemented as a shared core (`unichat-common/core`) consumed by two fork
workspaces: `unichat-notor` (direct TCP) and `unichat-tor` (adds the arti onion
transport behind the `tor` feature). Shared design notes live in
`unichat-common/docs/`. 54 shared-core tests pass; every phase was live-demoed
over TCP. (The arti onion transport compiles into the Tor fork and is wired into
every networked command, but a live onion connection was not exercisable in the
build environment — the transport-agnostic logic is covered by the loopback
tests.)

- **Phase 1 — `core/crypto` + `seal`:** ✅ X-Wing/AES-256-GCM/Argon2id/HKDF, the
  `.usealed` envelope, and the standalone `unichat-seal` CLI. *PQSpread's
  feature, upgraded to ML-KEM-768 + X25519 hybrid with filenames protected.*
- **Phase 2 — identity + storage:** ✅ profiles, Argon2id-unlocked encrypted
  store, Ed25519 identity + X-Wing keys, signed bundles, contacts.
- **Phase 3 — transport + handshake:** ✅ `core/transport` (trait + tcp + tor),
  `core/session` knock/approve + X-Wing station-to-station handshake, 1:1 chat.
  *Ricochet's feature, post-quantum.*
- **Phase 4 — sync + mailbox:** ✅ `core/sync` offline sealed messages +
  untrusted store-and-forward mailbox. *Briar's feature.*
- **Phase 5 — groups:** ✅ `core/groups` Cwtch-style untrusted-relay groups.
- **Phase 6 — sharing:** ✅ `core/share` ephemeral client-auth shares (auto-stop)
  + receive dropbox. *OnionShare's feature.*

Each phase read the referenced `_sub_src/` code, has a design note in
`unichat-common/docs/`, and shipped with tests before the next began.

---

## 5. Licensing note

Sources are GPLv3 (briar, onionshare, ricochet-refresh), MIT/Apache-2.0
(cwtch, RustCrypto), and AGPL-3.0 (pqspread). Porting code (not just ideas) from
the GPL/AGPL projects obligates the combined work to a compatible copyleft
license — plan for **AGPL-3.0-or-later** for the unified app, or keep ports
limited to the permissively licensed sources.
