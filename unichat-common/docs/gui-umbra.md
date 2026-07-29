# Umbra — the graphical client

"Umbra" is the brand for the desktop GUI shared by both forks. Brand plan and
mockups: the published design artifact (eclipse-corona identity — ink-navy
ground, corona-gold accent, monospace instrument wordmark).

## Where it lives

A single shared crate, `secure-comms-unified/unichat-gui/` (its own workspace
root so it stays out of the core test cycle), built on **egui/eframe 0.35**.
Each fork adds a thin `gui` binary (`umbra`) that depends on it:

```
unichat-gui/                     shared branded UI (lib)  ──depends──▶ unichat-common/core
  src/{lib,app,engine,theme,widgets}.rs
  src/tor_ep.rs                  #[cfg(feature="tor")] lazy arti endpoint
unichat-notor/gui/  (bin umbra)  Build{ tor_available:false }
unichat-tor/gui/    (bin umbra)  Build{ tor_available: cfg!(feature="tor") }, feature `tor` → unichat-gui/tor
```

The forks differ only in the injected transport, exactly like the CLI: the
no-Tor `umbra` is TCP-only; the Tor `umbra` (built `--features tor`) lights up
the onion-routing controls and routes engine operations through arti.

## Architecture — window never blocks

- **`engine`** runs on a background thread. The window sends `Command`s and
  receives `Event`s over channels; a Tor bootstrap or a network round-trip never
  freezes a frame. The engine owns the unlocked `Profile` + `UnlockedStore` and
  performs every core operation (unlock, seal, post/fetch, send/collect, host).
- **`app`** (the `eframe::App`) holds only plain view-model mirrors, drains
  engine events each frame, and renders. It never touches core key material
  directly — secrets stay on the engine thread.
- Network client ops select transport via a small macro: TCP, or (Tor build) a
  lazily-bootstrapped shared arti endpoint (`tor_ep`).
- Security-review **M1** is applied here: fetched group/mailbox messages are
  deduped by their authenticated message id, so a replaying relay can't surface
  duplicates.

## Screens (extensive user control)

- **Lock** — create or unlock an encrypted profile (passphrase).
- **Identity** — display name, fingerprint (read-aloud verification), copyable
  bundle, change passphrase.
- **Contacts** — add by bundle, mark verified/unverified (out-of-band check),
  remove; fingerprints shown.
- **Groups** — create/join by descriptor, per-group relay address, post + fetch
  (sealed to an untrusted relay), copy invite, leave.
- **Mailbox** — send an offline sealed message to a contact via a mailbox;
  collect your own.
- **Servers** — self-host an untrusted mailbox and group relay.
- **Settings** — transport (Tor toggle on the Tor build; fail-closed), security
  (KDF, forward-secrecy status, notification previews, lock now), appearance
  (text size, inspector visibility, raw-crypto readout), about.
- A persistent **security inspector** rail shows, at all times, the live posture:
  key exchange (X-Wing hybrid), cipher (AES-256-GCM), at-rest (Argon2id), and
  transport (onion/TCP).

## Build & run

```powershell
$env:Path = "C:\Users\Admin\tools\mingw64\bin;$env:USERPROFILE\.cargo\bin;$env:Path"
# No-Tor GUI:
cargo run  -p unichat-gui-app                       # from unichat-notor/
# Tor GUI (onion transport):
cargo run  -p unichat-gui-app --features tor        # from unichat-tor/
```

Both compile and launch on the Windows GNU + MinGW toolchain (eframe glow
backend). The window opens against the desktop session; the onion path shares
the Phase-3 live-testing caveat (no Tor network in the build sandbox), but all
TCP-transport operations are fully exercised by the core test suite and the CLI
demos.
