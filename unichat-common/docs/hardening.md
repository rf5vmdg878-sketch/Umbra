# Umbra hardening & threat model

This documents the security safeguards added for metadata resistance, at-rest
confidentiality, and tamper resistance — and, honestly, the limits of each.

## 1. Client IP privacy (relay)

**Clients never learn each other's IP.** The relay (`umbra-relay`, and
`core::call::relay`) is a rendezvous that cross-connects two sockets and copies
opaque bytes; neither peer is ever told the other's address. This is structural,
not a setting.

**The relay never logs client IPs.** A peer address is read only to evaluate the
optional allowlist and is dropped immediately in that scope — it is never logged,
counted per-source, echoed in an error, or persisted. Refusals/drops are counted
without attribution.

**Hiding IPs from the relay operator too — `private_mode`.** The operator's
machine still terminates the TCP connection and therefore sees the connecting
address at the socket level (unavoidable for any server). To remove even that,
set `private_mode = true`: the relay refuses to bind anything but loopback and
prints `torrc` for a co-located Tor onion service. Clients then reach it via
`.onion`, and every connection arrives from `127.0.0.1` (the local Tor daemon) —
the operator never sees a real client IP. Default is off so existing direct-TCP
/ LAN setups keep working.

## 2. At-rest encryption, including filenames (`storage::vault`)

The profile store is a **vault directory** of independently-encrypted objects:

- Every object's on-disk **filename is a keyed pseudonym** `HKDF(master_key,
  label)` — nothing on disk reveals what an object is. Contents are AES-256-GCM
  under a per-object key from a fresh salt; the label's name tag is the AEAD AAD,
  so object files can't be swapped between labels.
- The only fixed name is `keyring`, the passphrase envelope (a wrapped random
  master key). It contains no plaintext.
- Display name, contacts, groups, keys, and cached data all live inside
  opaque-named encrypted objects. Legacy single-file `.profile` stores are
  migrated into a vault automatically on first open.
- **Tor state at rest** (`private_mode`/onion builds) is packed into a vault
  object and only unpacked to a scratch dir while running, then wiped — so an
  offline disk doesn't reveal that the machine runs an onion service.

**Residual, by design:** an observer with filesystem access still sees that some
encrypted objects exist, their sizes, and their count — just never their names
or contents. **Deliberate exception:** files the user chooses to download/copy
out of an opened chat are saved **plaintext** to the location they pick.

## 3. Tamper-evidence (`core::integrity`)

Every Umbra binary verifies, at startup and every 30 s at runtime, that its own
executable and declared assets match `umbra.manifest` — a list of SHA-256 hashes
**Ed25519-signed by the release key** (public key compiled into the app). Any
mismatch (a stripped, rewritten, or back-doored binary; a swapped `symcrypt.dll`)
makes it **refuse to run**. Release builds also refuse to run under a debugger.

Arming it (release tooling):

```
umbra-manifest genkey  <secret.key>          # once; keep the key OFFLINE
#  → paste the printed RELEASE_PUBKEY into core/src/integrity.rs, rebuild
umbra-manifest sign    <secret.key> <dir>     # after every build → dir/umbra.manifest
umbra-manifest verify  <pubkey-hex> <dir>     # sanity check
```

Developer builds (no key provisioned, or no manifest present) run normally with a
one-line "unverified" notice — enforcement only kicks in for signed releases.

### The hard limit (read this)

**Pure software cannot make a binary immutable.** Anything the app checks, an
attacker who can rewrite the files can also patch out. The manifest gives strong
tamper-*evidence* and stops naive file-swapping; true immutability comes only
from the OS layer:

- **`scripts/harden.ps1`** — owner-only, inheritance-off ACLs on the install dir
  plus the read-only attribute on every exe/dll/manifest, so another process
  can't rewrite them in the first place.
- **Authenticode signing** (`signtool`) — so Windows itself refuses to load an
  unsigned/modified binary. This requires a code-signing certificate and is the
  only layer that is actually enforced below the app.

Use all three together; each covers the others' gaps.
