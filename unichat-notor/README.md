# unichat (no-Tor fork)

No-Tor build of the unified secure communications suite: transport is direct TCP
(LAN/clearnet or testing). Shares all library code with the Tor fork via
`../unichat-common`.

## Structure

This fork is a thin workspace containing the `cli` and `gui` crates. Everything
else is shared:
- Engine library + offline `seal` tool: `../unichat-common` (`unichat-core`,
  `unichat-seal`), with design notes in `../unichat-common/docs`.
- Branded GUI ("Umbra"): `../unichat-gui` (shared with the Tor fork).
- This fork's `cli`/`gui` depend on the shared crates without the `tor` feature.

## GUI

```powershell
cargo run -p unichat-gui-app     # launches the Umbra desktop app (bin: umbra)
```

See `../unichat-common/docs/gui-umbra.md`.

## Status: Phases 1–6 complete (suite finished)

- **Phase 1** — crypto core on Microsoft SymCrypt: X-Wing (ML-KEM-768 + X25519),
  AES-256-GCM `.usealed` envelope, HKDF, Argon2id.
- **Phase 2** — Ed25519 identities, signed key bundles, contacts, encrypted
  profile store.
- **Phase 3** — post-quantum mutually-authenticated session (`chat`) over TCP.
- **Phase 4** — offline store-and-forward: `mailbox` node + `msg send/collect`.
- **Phase 5** — untrusted-relay group chat: `relay serve` + `group
  create/join/post/fetch`.
- **Phase 6** — ephemeral file sharing: `share send/download` (one-shot,
  auto-stop) + `share receive/upload` (dropbox).

## Build

```powershell
$env:Path = "C:\Users\Admin\tools\mingw64\bin;$env:USERPROFILE\.cargo\bin;$env:Path"
cargo build --release        # builds cli against the shared core
# The offline `unichat-seal` tool builds from ../unichat-common.
```

## Try it

```powershell
$uc = "target\release\unichat.exe"
# Profiles + exchange bundles:
$env:UNICHAT_PASSPHRASE="a"; & $uc profile create --store alice.profile --name Alice; & $uc profile bundle --store alice.profile > alice.bundle
$env:UNICHAT_PASSPHRASE="b"; & $uc profile create --store bob.profile --name Bob;   & $uc profile bundle --store bob.profile   > bob.bundle
$env:UNICHAT_PASSPHRASE="a"; & $uc contact add --store alice.profile --alias bob   --bundle bob.bundle

# Live chat (Phase 3): Bob serves, Alice connects.
& $uc chat serve --store bob.profile --bind 127.0.0.1:9878 --accept-unknown
& $uc chat send  --store alice.profile --to 127.0.0.1:9878 --knock Alice --message "hi"

# Offline messaging (Phase 4): run a mailbox, send while Bob is offline, collect later.
& $uc mailbox serve --bind 127.0.0.1:9900
& $uc msg send    --store alice.profile --to bob --via 127.0.0.1:9900 --message "offline hi"
& $uc msg collect --store bob.profile   --via 127.0.0.1:9900

# Group chat (Phase 5): untrusted relay + share the invite descriptor to join.
& $uc relay serve --bind 127.0.0.1:9910
& $uc group create --store alice.profile --name devteam     # prints an invite descriptor
& $uc group join   --store bob.profile   --descriptor "unichat-group-v1:..."
& $uc group post   --store alice.profile --name devteam --via 127.0.0.1:9910 --message "hi team"
& $uc group fetch  --store bob.profile   --name devteam --via 127.0.0.1:9910

# Ephemeral file share (Phase 6): one-shot download (auto-stops), or a dropbox.
& $uc share send     --file secret.pdf --downloads 1        # prints a share descriptor
& $uc share download --from 127.0.0.1:9920 --descriptor "unichat-share-v1:..." --out got.pdf
& $uc share receive  --out inbox                            # prints a receive descriptor
& $uc share upload   --to 127.0.0.1:9921 --descriptor "unichat-receive-v1:..." --file leak.pdf
```
