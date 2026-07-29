# Third-party notices

The original source code in this repository is Copyright (c) 2026
rf5vmdg878-sketch and licensed under the MIT License (see `LICENSE`). That
copyright and license apply to the code written for this project; they do **not**
extend to the third-party components below, each of which remains under its own
license and the copyright of its own authors.

## Bundled / linked cryptography

- **Microsoft SymCrypt** — the FIPS-validated crypto library providing
  ML-KEM-768, AES-256-GCM, X25519, SHA-3/SHAKE, HKDF, and the DRBG. Licensed
  MIT, Copyright (c) Microsoft Corporation.
  https://github.com/microsoft/SymCrypt
  The prebuilt `symcrypt.dll` / `symcrypt.lib` are **not redistributed** in this
  repository; download the official release and place it under
  `unichat-common/vendor/symcrypt/dll/` (see that folder's README).

## Rust dependencies (fetched by Cargo, under their own licenses)

- **symcrypt / symcrypt-sys** (Microsoft) — MIT OR Apache-2.0
- **argon2, x-wing, ml-kem** (RustCrypto) — MIT OR Apache-2.0
- **ed25519-dalek, curve25519-dalek** — BSD-3-Clause
- **egui / eframe** (Umbra GUI) — MIT OR Apache-2.0
- **arti-client and the tor-\* crates** (Tor Project, used by the Tor fork) —
  MIT OR Apache-2.0
- plus serde, zeroize, subtle, base64, thiserror, clap, rpassword, and other
  crates, each under permissive (MIT/Apache-2.0) terms.

## Design provenance

This project's *design* was informed by studying several open-source
metadata-resistant messengers. No source code from them was copied; only ideas
and architectural approaches were referenced. They are credited here:

- **Cwtch** (Open Privacy) — untrusted-relay groups, encrypted profiles.
- **Briar** — transport-agnostic store-and-forward, mailbox model. (GPL-3.0)
- **Ricochet Refresh** — onion-address identity, knock/approve. (GPL-3.0)
- **OnionShare** — ephemeral client-authorized shares, receive mode. (GPL-3.0)
- **PQSpread** (Forkbomb) — serverless post-quantum file exchange. (AGPL-3.0)

Because these are strong-copyleft projects, if any actual code (not just ideas)
from them is later incorporated, the affected work would need to adopt a
compatible copyleft license.
