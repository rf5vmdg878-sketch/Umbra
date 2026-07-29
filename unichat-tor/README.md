# unichat (Tor fork)

Tor build of the unified secure communications suite: adds a Tor v3
onion-service transport (via arti) alongside direct TCP. Shares all library code
with the no-Tor fork via `../unichat-common`.

## Structure

Thin workspace with the `cli` and `gui` crates. Shared engine library + offline
`seal` tool live in `../unichat-common` (`unichat-core`, `unichat-seal`); the
branded GUI ("Umbra") lives in `../unichat-gui` (shared with the no-Tor fork);
design notes in `../unichat-common/docs`. This fork's crates depend on the
shared crates and enable the `tor` feature to pull in the arti onion transport.

## GUI

```powershell
cargo run -p unichat-gui-app --features tor   # Umbra desktop app with onion transport (bin: umbra)
```

See `../unichat-common/docs/gui-umbra.md`.

## Status: Phases 1–6 complete (suite finished)

Same features as the no-Tor fork (crypto, identities/storage, session chat,
offline mailbox, untrusted-relay groups, ephemeral file sharing), plus a Tor
onion transport for `chat`, `mailbox`/`msg`, `group`/`relay`, and `share` (all
accept `--tor`).

## Build

```powershell
$env:Path = "C:\Users\Admin\tools\mingw64\bin;$env:USERPROFILE\.cargo\bin;$env:Path"

cargo build --release                          # TCP transport only (fast)
cargo build --release -p unichat-cli --features tor   # + Tor onion transport (pulls in arti)
```

MinGW-w64 binutils must be on PATH. The Tor build bundles SQLite from source
(arti's `static-sqlite`) so no system libsqlite3 is needed.

## Chat / mailbox over Tor

```powershell
$uc = "target\release\unichat.exe"     # built with --features tor
& $uc chat serve  --store bob.profile --tor --accept-unknown         # prints a .onion
& $uc chat send   --store alice.profile --to <onion>.onion:9878 --tor --knock Alice --message "hi"
& $uc mailbox serve --tor                                            # onion mailbox
& $uc msg send    --store alice.profile --to bob --via <onion>.onion:9900 --tor --message "offline hi"
& $uc msg collect --store bob.profile --via <onion>.onion:9900 --tor
```

**Live-testing caveat:** the onion transport compiles and is wired into every
command, but a live onion connection was not exercised in the build environment
(no Tor bootstrap available). All session/mailbox logic is transport-agnostic
and covered by the shared loopback tests; only the arti wiring is un-exercised at
runtime. Everything works and is tested over TCP.
