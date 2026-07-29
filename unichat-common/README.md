# unichat-common — shared core for both forks

This workspace holds the code shared by the no-Tor and Tor forks, so it is
edited **once**:

- `core/` (`unichat-core`) — the entire engine library: `crypto` (Phase 1),
  `identity` + `storage` (Phase 2), `session` + `transport` (Phase 3), and
  `sync` (Phase 4). The Tor onion transport lives here too, behind the `tor`
  cargo feature (off by default).
- `seal/` (`unichat-seal`) — the offline file-encryption CLI (identical for both
  forks; built here once).
- `vendor/symcrypt/` — the vendored Microsoft SymCrypt DLL/LIB (v103.11.0),
  referenced by both forks via their `.cargo/config.toml`.

## Layout

```
secure-comms-unified/
  unichat-common/     <- this: shared core + seal + vendored SymCrypt
  unichat-notor/      <- fork: cli only, TCP transport (depends on ../unichat-common/core)
  unichat-tor/        <- fork: cli only, TCP + Tor (core built with feature "tor")
```

Each fork is a thin workspace containing just its `cli` crate, which depends on
`../unichat-common/core` by path. The forks differ only in transport: the Tor
fork enables the core's `tor` feature and its CLI wires up the onion transport.

## Build & test the shared core

```powershell
$env:Path = "C:\Users\Admin\tools\mingw64\bin;$env:USERPROFILE\.cargo\bin;$env:Path"
cargo test            # 37 tests across phases 1–4
cargo build --release # core + seal
```

MinGW-w64 binutils must be on PATH (rustup's minimal toolchain lacks
`dlltool`/`as`). See `docs/` for per-phase design notes.
