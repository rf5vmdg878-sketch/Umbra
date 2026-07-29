# Umbra

A **post-quantum, metadata-resistant secure messenger** built on Microsoft
SymCrypt. Every key exchange is the hybrid **X-Wing (ML-KEM-768 + X25519)**;
messages and files are sealed with **AES-256-GCM**; profiles are encrypted at
rest with **Argon2id**.

> Copyright (c) 2026 rf5vmdg878-sketch — MIT licensed (see `LICENSE`).
> Third-party components: see `THIRD-PARTY-NOTICES.md`.

## What's inside

| Path | What it is |
|---|---|
| `unichat-common/` | Shared engine (`unichat-core`) + offline file tool (`unichat-seal`) + design docs |
| `unichat-notor/` | Fork with the direct-TCP transport (LAN / testing) |
| `unichat-tor/` | Fork adding a Tor v3 onion-service transport (arti), behind `--features tor` |
| `unichat-gui/` | **Umbra** — the shared desktop GUI (egui/eframe) |
| `UNIFIED_BUILD_SPEC.md` | The design brief and phase plan |

Features span six phases: hybrid-PQ crypto core, encrypted identities/storage,
mutually-authenticated 1:1 chat, offline store-and-forward mailbox,
untrusted-relay group chat, and ephemeral file sharing. See
`unichat-common/docs/` for per-phase design notes and the security review.

## Building (Windows)

1. **Get SymCrypt.** Download the official release DLL/LIB and place them in
   `unichat-common/vendor/symcrypt/dll/` (see that folder's `README.md`). They
   are not redistributed here.
2. **Toolchain.** Rust (`x86_64-pc-windows-gnu`) with MinGW-w64 binutils on
   PATH (the bundled rustup linker lacks `dlltool`/`as`).
3. Build:
   ```
   cargo build --release          # from unichat-common (core + seal)
   cargo run  -p unichat-gui-app  # from unichat-notor — launches the Umbra app
   ```

The companion **umbra-relay** repository is a private, encrypted relay server
for this messenger; clone it alongside this repo (as `../umbra-relay`).

## License

MIT. This license covers the original code here; bundled/linked third-party
components keep their own licenses (`THIRD-PARTY-NOTICES.md`). The design was
informed by GPL/AGPL messengers (Briar, OnionShare, Ricochet, Cwtch, PQSpread) —
ideas only, no code copied.
