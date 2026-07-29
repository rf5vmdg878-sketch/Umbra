# Vendored SymCrypt (not committed)

This project links Microsoft **SymCrypt** for its FIPS-validated primitives
(ML-KEM-768, AES-256-GCM, X25519, SHA-3/SHAKE, HKDF, DRBG). The prebuilt binary
is **not redistributed** in this repository.

To build, download the official Windows release and place the files here:

```
unichat-common/vendor/symcrypt/dll/symcrypt.dll
unichat-common/vendor/symcrypt/dll/symcrypt.lib
```

Get them from the SymCrypt releases page:
https://github.com/microsoft/SymCrypt/releases  (e.g. the
`symcrypt-windows-amd64-release-*.zip` asset; this project was built against
v103.11.0).

`.cargo/config.toml` sets `SYMCRYPT_LIB_PATH` to `vendor/symcrypt/dll`, and each
crate's `build.rs` copies `symcrypt.dll` next to the produced executables.

SymCrypt is MIT-licensed, Copyright (c) Microsoft Corporation.
