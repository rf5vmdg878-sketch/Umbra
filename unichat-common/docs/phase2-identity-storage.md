# Phase 2 design note — identity + encrypted storage

## Identity (`core/src/identity/`)

- **Ed25519 identity key** — the long-term root of trust, matching v3
  onion-service identities so Phase 3's Tor transport can reuse it directly.
  SymCrypt exception (like Argon2id): SymCrypt implements no EdDSA (ECDSA on
  NIST curves only — verified against `inc/symcrypt.h`), so the audited
  `ed25519-dalek` 3.0 (dalek family, same as Tor's arti) is used, pinned.
- **KeyBundle** — the contact-exchange blob:
  `unichat-bundle-v1:base64(identity_pk(32) || xwing_pk(1216) || sig(64))`.
  The Ed25519 signature covers a domain-separated message
  (`"unichat-key-bundle-v1\0" || xwing_pk`), binding the post-quantum
  encryption key to the identity — the spec's "X-Wing keypair signed by the
  identity key". **Decode always verifies** (`verify_strict`); an invalid
  bundle can never become a contact.
- **Fingerprint** — SHA3-256 (SymCrypt) over both public keys, shown as five
  hex groups for out-of-band comparison.
- **Contacts** — alias + both public keys + state
  (`pending`/`approved`/`blocked`; `pending` is reserved for Phase 3's
  Ricochet-style knock flow). Duplicate aliases and adding one's own identity
  are rejected.

## Encrypted profile store (`core/src/storage/`)

`UPROFDB` v1, the Cwtch "everything encrypted at rest" model with the spec's
master-key envelope:

- A random 256-bit **master key (MK)** from SymCrypt's DRBG encrypts the body;
  the passphrase only wraps MK via Argon2id → AES-256-GCM. Changing the
  passphrase rewraps 48 bytes; body encryption is untouched.
- The body (profile JSON: display name, key seeds, contacts, timestamps) is
  encrypted under `HKDF(MK, fresh 32-byte salt per save)` — nonce reuse is
  structurally impossible, and **no metadata exists in plaintext at rest**.
- AAD chains: the MK wrap authenticates the KDF header; the body authenticates
  the entire header. Tampering with salt/params/wrap/body all fail closed
  (tested byte-by-byte per region), plus the Argon2 parameter floor blocks
  downgrade.
- Saves are atomic (temp file + rename).

## CLI (`cli/`, binary `unichat`)

`profile create|info|bundle|change-passphrase`, `contact add|list|remove`.
Passphrase via prompt or `UNICHAT_PASSPHRASE` / `UNICHAT_NEW_PASSPHRASE` for
automation. This crate is the seed of the Phase 3+ client.

## Tests (`core/tests/identity_storage.rs`)

Bundle round-trip + per-region tamper rejection; store round-trip with
contacts; wrong passphrase; store tamper matrix; passphrase change keeps data
(and old passphrase stops working); duplicate/self contact rejection; and an
end-to-end proof that a stored contact's bundle key seals an envelope the
contact's own profile decrypts.
