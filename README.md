# Umbra

A **post-quantum, metadata-resistant secure messenger** built on Microsoft
SymCrypt. Every key exchange is the hybrid **X-Wing (ML-KEM-768 + X25519)**;
messages, files, and live calls are sealed with **AES-256-GCM**; profiles are
encrypted at rest with **Argon2id** in an opaque vault (even filenames are
encrypted). It runs on **Windows and Linux**, with an optional Tor v3
onion-service transport.

> Copyright (c) 2026 rf5vmdg878-sketch — MIT licensed (see `LICENSE`).
> Third-party components: see `THIRD-PARTY-NOTICES.md`.

## Features

- **Hybrid post-quantum crypto** — X-Wing (ML-KEM-768 + X25519), AES-256-GCM,
  HKDF-SHA-256, Ed25519, Argon2id, all via SymCrypt (except Ed25519/Argon2id).
- **1:1 chat, groups, offline mailbox, ephemeral file sharing** over an
  untrusted relay — the relay only ever sees ciphertext.
- **End-to-end encrypted file transfer and live voice/video calls** using your
  own relay for rendezvous (no third party). Real microphone/camera capture
  (cpal + V4L2/WASAPI); video is MJPEG, audio is PCM.
- **Metadata resistance** — clients never learn each other's IP; the relay never
  logs client IPs; optional loopback-only *private mode* behind a Tor onion
  service so even the operator never sees a real client IP.
- **Encrypted at rest, down to filenames** — the profile store is an opaque
  object vault; Tor onion-service keys are encrypted at rest too.
- **Tamper-evidence** — every binary verifies an Ed25519-signed manifest at
  startup and refuses to run if altered (see `unichat-common/docs/hardening.md`).

## Quick start

The `umbra-build` tool downloads what it needs, builds the app, and (optionally)
packages a portable archive. The bootstrap scripts install the toolchain first.

**Linux**
```sh
./scripts/bootstrap.sh app --package            # non-Tor desktop app + CLI
./scripts/bootstrap.sh app --torify --package   # Tor-hardened (onion transport)
./scripts/bootstrap.sh relay --torify           # private-mode relay + torrc template
```

**Windows** (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 app --package
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 app --torify --package
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 relay --torify
```

Archives land in `dist/` (`.tar.gz` on Linux, `.zip` on Windows). See
[`docs/INSTALL.md`](docs/INSTALL.md) to install one, and
[`docs/BUILD.md`](docs/BUILD.md) for the full build-tool reference.

### Non-Tor vs. `--torify`

| | Non-Tor (default) | `--torify` |
|---|---|---|
| **App** | direct-TCP fork (`unichat-notor`) | onion-transport fork (`unichat-tor`, arti) |
| **Relay** | binds `0.0.0.0`, never logs IPs | binds loopback only + generates a private-mode config and a `torrc` onion template so the relay never sees a client IP |

## What's inside

| Path | What it is |
|---|---|
| `unichat-common/` | Shared engine (`unichat-core`), offline file tool (`unichat-seal`), `umbra-build`, `umbra-manifest`, design docs |
| `unichat-notor/` | Direct-TCP fork (LAN / no Tor) |
| `unichat-tor/` | Tor v3 onion-service fork (arti), behind `--features tor` |
| `unichat-gui/` | **Umbra** — the shared desktop GUI (egui/eframe) |
| `unichat-media/` | Real microphone/camera capture + playback for calls |
| `scripts/` | `bootstrap.*` (setup + build), `harden.ps1` (OS lockdown), `sign-release.ps1` |
| `docs/` | Build, install, usage; security posture in `unichat-common/docs/hardening.md` |

The companion **umbra-relay** repository is the encrypted relay server; clone it
alongside this repo (as `../umbra-relay`) so `umbra-build relay` can find it.

## Platform notes

- **Windows**: builds with the `x86_64-pc-windows-gnu` toolchain; SymCrypt ships
  vendored under `unichat-common/vendor/symcrypt/`.
- **Linux**: `bootstrap.sh` installs ALSA + V4L2 dev headers (mic/camera), a C
  toolchain, and `clang`; `umbra-build` fetches the SymCrypt `.so`. First Linux
  compile happens on the Linux host — this is the tool's whole purpose.

## License

MIT. This license covers the original code here; bundled/linked third-party
components keep their own licenses (`THIRD-PARTY-NOTICES.md`). The design was
informed by GPL/AGPL messengers (Briar, OnionShare, Ricochet, Cwtch, PQSpread) —
ideas only, no code copied.
