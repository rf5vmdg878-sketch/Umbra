# Phase 1 design note — crypto core + `unichat-seal`

## Backend decision: Microsoft SymCrypt

Per project direction, the cryptographic primitives come from **Microsoft
SymCrypt** — the FIPS-validated library that ships inside Windows — vendored as
the official prebuilt release DLL (`vendor/symcrypt/`, v103.11.0) and consumed
through Microsoft's official Rust bindings (`symcrypt` 0.5.1 / `symcrypt-sys`
0.4.0, pinned).

Terminology note: ML-KEM-768 is the NIST post-quantum standard (FIPS 203,
originally CRYSTALS-Kyber); SymCrypt is Microsoft's *implementation* of that
standard. "Quantum-resistant" is the accurate claim, and the X-Wing hybrid with
X25519 hedges against flaws in either component.

| Primitive | Source | Route |
|---|---|---|
| ML-KEM-768 (FIPS 203) | SymCrypt | direct FFI (`core/src/crypto/ffi.rs`) — Microsoft's Rust bindings predate ML-KEM; the symbols are exported by the same DLL |
| X25519 (Curve25519 ECDH) | SymCrypt | `symcrypt::ecc` |
| SHAKE-256, SHA3-256 | SymCrypt | FFI one-shot / `symcrypt::hash` |
| AES-256-GCM | SymCrypt | `symcrypt::gcm` |
| HKDF-SHA-256 | SymCrypt | `symcrypt::hkdf` |
| Randomness | SymCrypt FIPS DRBG | `SymCryptRandom` |
| Argon2id (RFC 9106) | RustCrypto `argon2` (audited) | SymCrypt has no memory-hard KDF; a fast KDF over human passphrases would weaken security, so this one primitive is sourced outside SymCrypt |

## X-Wing hybrid KEM

`core/src/crypto/xwing.rs` implements X-Wing
(draft-connolly-cfrg-xwing-kem-06): ML-KEM-768 + X25519 with the SHA3-256
combiner and SHAKE-256 seed expansion. SymCrypt's `PRIVATE_SEED` import format
(d‖z, 64 bytes) matches the draft's ML-KEM key-derivation exactly. No code path
uses ML-KEM or X25519 alone.

**Validation** (`core/tests/`):
- `xwing_vectors.rs` — official draft test vectors: seed → public key, and
  (seed, ct) → shared secret. (Encapsulation is DRBG-randomized, so its vector
  cannot be replayed.)
- `interop.rs` — cross-vendor tests against the independent RustCrypto `x-wing`
  implementation in both directions (dev-dependency only; ships nothing).
- `envelope.rs` — round-trips (empty/small/multi-chunk), wrong-key, per-region
  byte flips, truncation, record reorder, cross-envelope splice, Argon2id
  keyfile round-trip + parameter-downgrade rejection.

## `.usealed` envelope

See module docs in `core/src/crypto/envelope.rs`. Design properties:
- fresh X-Wing encapsulation per file; per-file key via HKDF-SHA-256 with a
  random 32-byte salt;
- AES-256-GCM records with **counter nonces** (never random, never reused);
- every record's AAD binds the header hash, record index, and final flag —
  reorder/truncate/extend/splice all fail authentication;
- filename + size travel encrypted in record 0 (fixes PQSpread's filename
  leak); decrypted size must equal the declared size;
- 1 MiB streaming chunks — constant memory for arbitrarily large files;
- decryption fails closed: the CLI writes to a `.part` temp file and deletes it
  on any authentication error.

## Key files

- Public: `unichat-xwing-pub-v1:<base64>` text, freely shareable.
- Secret: 32-byte seed, by default wrapped with Argon2id (64 MiB, t=3, p=4;
  parameters stored per file, floored at decode to block downgrade tampering)
  and AES-256-GCM with the preamble as AAD.

## Toolchain / linking

- `SYMCRYPT_LIB_PATH` is set by `.cargo/config.toml` to `vendor/symcrypt/dll`;
  `symcrypt-sys`'s build script links `symcrypt.lib` from there.
- `core/build.rs` copies `symcrypt.dll` next to built binaries and test
  executables.
- Host toolchain: `x86_64-pc-windows-msvc` (the configuration Microsoft
  supports for rust-symcrypt).

## Phase 1 deliverable

`unichat-seal` CLI: `keygen` / `encrypt` / `decrypt` / `pubkey` — PQSpread's
serverless file-exchange feature with hybrid post-quantum encryption,
streaming AEAD, protected filenames, and passphrase-protected keys.
