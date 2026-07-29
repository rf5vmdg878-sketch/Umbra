# Building Umbra

Two layers: **bootstrap scripts** set up the machine, then the **`umbra-build`**
tool does the actual builds and packaging. You can also drive `cargo` directly.

## Bootstrap (recommended)

The bootstrap script installs the Rust toolchain (and, on Linux, the system
build dependencies), builds `umbra-build`, and forwards the rest of your
arguments to it.

**Linux** — `scripts/bootstrap.sh` auto-detects `apt`/`dnf`/`pacman` and installs
`curl`, a C toolchain, `pkg-config`, ALSA dev (`libasound2-dev`), V4L2 dev
(`libv4l-dev`), `clang`, and `tar`:
```sh
./scripts/bootstrap.sh <target> [flags]
```

**Windows** — `scripts/bootstrap.ps1` installs rustup with the
`x86_64-pc-windows-gnu` toolchain (its bundled `rust-mingw` provides the linker):
```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 <target> [flags]
```

## `umbra-build` reference

```
umbra-build [app|relay|all] [flags]
```

| Target | Builds |
|---|---|
| `app` (default) | the desktop app (`umbra`) + CLI (`unichat`) |
| `relay` | `umbra-relay` (found at `../umbra-relay` by default) |
| `all` | both |

| Flag | Effect |
|---|---|
| `--torify` (or `-torify`) | Tor-hardened variant: the app's onion-transport fork; for the relay, also writes a private-mode `umbra-relay.toml` + `torrc.onion.sample` |
| `--debug` | debug build (default is release) |
| `--no-media` | build the app without real mic/camera capture |
| `--sign <keyfile>` | Ed25519-sign the integrity manifest after building (arms tamper-evidence) |
| `--package` | emit a portable archive (`.zip` on Windows, `.tar.gz` on Linux) into `dist/` |
| `--out <dir>` | archive output directory |
| `--relay-path <dir>` | where the `umbra-relay` repo lives |
| `--symcrypt-url <url>` | override the Linux SymCrypt download URL |
| `--skip-symcrypt` | assume SymCrypt is already present |

### Examples
```sh
umbra-build app                                   # non-Tor app, release
umbra-build app --torify --package                # Tor app, packaged
umbra-build all --package --sign ~/.umbra-release-signing.key
umbra-build relay --torify                        # private-mode relay + torrc
```

## SymCrypt

- **Windows**: vendored under `unichat-common/vendor/symcrypt/` (DLL + import
  lib). Nothing to download.
- **Linux**: `umbra-build` downloads `libsymcrypt.so` into
  `unichat-common/vendor/symcrypt/linux/` and points cargo at it via
  `SYMCRYPT_LIB_PATH`, baking `-rpath,$ORIGIN` so the packaged binary finds the
  co-located `.so`. If the default download URL 404s (release assets move),
  grab the correct URL from <https://github.com/microsoft/SymCrypt/releases>
  and pass `--symcrypt-url`.

## Building with cargo directly

From a fork directory (`unichat-notor` or `unichat-tor`):
```sh
cargo build --release                 # app + CLI, media on (default)
cargo build --release --features tor  # (unichat-tor) enable the onion transport
cargo build --release --no-default-features   # without real mic/camera
```
On Linux, set `SYMCRYPT_LIB_PATH` to your `libsymcrypt.so` directory first.

## Arming tamper-evidence (release signing)

`RELEASE_PUBKEY` is compiled into the binaries. After **every** release build,
re-sign or the app will refuse to launch:
```sh
scripts/sign-release.ps1 -Key <keyfile>     # Windows
umbra-build app --sign <keyfile>            # or via the build tool, any OS
```
Generate a keypair once with `umbra-manifest genkey <keyfile>` and paste the
printed `RELEASE_PUBKEY` into `unichat-common/core/src/integrity.rs`. Keep the
private key **offline**. Deleting `umbra.manifest` lets a build run unsigned
(no tamper protection) — useful during development. See
`unichat-common/docs/hardening.md`.
