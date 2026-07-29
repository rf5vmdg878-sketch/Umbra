# Using Umbra

## The desktop app (`umbra`)

1. **Create or unlock a profile.** The profile is an encrypted vault directory
   (opaque filenames); pick where it lives and set a passphrase.
2. **Share your bundle.** Your contact bundle (`unichat-bundle-v1:…`) is your
   public identity — send it to a peer out of band; paste theirs to add them.
   Verify fingerprints in person / over a trusted channel.
3. **Chat & groups** route through a relay you configure; the relay only sees
   ciphertext.
4. **Calls & file transfer** (Calls screen): agree a call-id with your peer,
   enter your relay, then one side **Dial**s and the other **Answer**s. With the
   `media` feature (default) this uses your real mic/camera; the peer's video
   shows on screen and their audio plays. Files can be sent E2E; downloaded
   files are saved **plaintext** where you choose (by design).
5. **Tor** (torify build): toggle routing over the onion transport. Onion-service
   keys are encrypted at rest in the vault and only unpacked while unlocked.

## The CLI (`unichat`)

```
unichat profile create|unlock ...
unichat contact add|list ...
unichat chat serve|send ...
unichat group create|join|post|fetch ...        # + relay serve
unichat msg send|collect ...                     # offline mailbox
unichat mailbox serve ...
unichat share send|download|receive|upload ...
unichat call dial|answer|send-file|recv-file --relay <addr> --id <call-id> [--video]
```
Run `unichat <command> --help` for details. On the Tor fork, most commands take
`--tor` (and `--state-dir`) to route over an onion service. Real mic/camera
calls run on the direct-TCP path (`call dial/answer` without `--tor`).

Automation: set `UNICHAT_PASSPHRASE` / `UNICHAT_NEW_PASSPHRASE` to avoid prompts.

## Running the relay

```
umbra-relay --gen-config > umbra-relay.toml     # then edit
UMBRA_RELAY_PASSPHRASE=... umbra-relay umbra-relay.toml
```

Key config (`umbra-relay.toml`):

| Key | Meaning |
|---|---|
| `group_bind` / `mailbox_bind` / `call_bind` | service binds; empty disables one |
| `allow_ips` | source allowlist (empty = any); IPs are **never logged** |
| `max_connections`, `idle_timeout_secs` | connection cap + idle timeout |
| `spool_path`, `snapshot_interval_secs` | encrypted persistence |
| `private_mode` | refuse non-loopback binds; reachable only via a co-located Tor onion service (the relay then never sees a real client IP) |

The spool is encrypted (Argon2id + AES-256-GCM) under the operator passphrase.
Clients never learn each other's IP — the relay only cross-pumps ciphertext.

### Private (onion) relay

Build with `umbra-build relay --torify` (writes `umbra-relay.toml` with
`private_mode = true` + `torrc.onion.sample`), point your system Tor at the
generated `torrc`, and hand clients the `.onion` hostname. See
`../unichat-common/docs/hardening.md` for the full metadata-resistance model and
its limits.

## Security posture (read this)

See **`../unichat-common/docs/hardening.md`** for the honest threat model:
what's enforced (E2E crypto, opaque at-rest storage, no IP logging, tamper-
evidence) versus what needs operator setup (OS ACLs, Authenticode, Tor onion
fronting) — and the real limits (no pure-software immutability; Tor state is
plaintext while the app runs; live A/V needs your hardware to validate).
