# Phase 6 design note — ephemeral file sharing

Phase 6 delivers OnionShare's feature: share a file for a bounded number of
one-shot downloads, or run an anonymous receive dropbox — with client
authorization and content sealed end-to-end so the carrier (and, in receive
mode, the host until it decrypts) only ever sees ciphertext. Runs over any
`transport` (LAN TCP, or a Tor onion service in that fork), completing the
suite.

## Capability descriptors (`share::Share` / `ReceiveShare`)

Every share has a public 16-byte id and a secret 32-byte **share key** — the
OnionShare private-key / client-authorization analog. The **descriptor**
(`unichat-share-v1:` for download, `unichat-receive-v1:` for a dropbox) encodes
`label ‖ id ‖ key ‖ size` and is the capability: hand it to the intended party
over a secure channel (Phase 3 chat or a Phase 4 sealed message). Anyone with
it can transfer; anyone without it cannot connect meaningfully or decrypt.

## Content sealing (`seal_content` / `open_content`)

File bytes and filename are encrypted with a key derived from the share key —
`HKDF-SHA256(share_key, random 32-byte salt, "unichat-share-content-v1")` — under
AES-256-GCM with the share id as associated data. So the download host relays
sealed bytes it cannot read, and a receive host stores sealed uploads until it
chooses to decrypt (never executing them). Whole-file in memory; large-file
streaming is future work.

## Host + client (`share::host`)

The [`ShareHost`] holds registered send-shares and receive-dropboxes in memory.
Before any transfer, the client proves knowledge of the share key with a
**challenge-response**: the host issues a random nonce, the client returns
`mac = SHA3-256(domain ‖ mode ‖ share_key ‖ nonce)`, and the host compares in
**constant time** (`subtle`). The `mode` byte separates download from upload so
a proof for one can't be replayed for the other.

- **Send** carries a **download budget**; each successful download decrements it
  and the share is removed at zero — OnionShare's auto-stop.
- **Receive** stores size-bounded (`MAX_UPLOAD_SIZE`) sealed uploads; the host
  decrypts them with `open_content`.

Wire protocol (`u32-le length ‖ JSON`): `DownloadReq→Challenge→DownloadAuth→
Content`; `UploadReq→Challenge→UploadAuth→Ok`.

## CLI

`share send --file F [--downloads N]` (prints a descriptor, serves, auto-stops);
`share download --from ADDR --descriptor D --out F`; `share receive --out DIR`
(prints a receive descriptor, decrypts uploads into DIR); `share upload --to
ADDR --descriptor D --file F`. The Tor fork adds `--tor` to publish/reach the
host as an onion service. Received filenames are sanitized to a safe basename.

## Tests (`core/tests/share.rs`, 9/9)

Content seal/open round-trip; wrong-key and tamper rejection; send/receive
descriptor round-trips (and a send descriptor rejected as a receive one);
one-shot download then auto-stop; wrong token cannot download (budget
untouched); multi-download budget honored then refused; receive dropbox
round-trip (host decrypts two sealed uploads); wrong token cannot upload; and
send/receive id isolation.

## Limitations / future work

- **Whole-file in memory** — large shares need chunked streaming (the Phase 1
  envelope's chunking can be generalized to a symmetric key for this).
- **Metadata:** the host learns share ids, sizes, and timing. Auth proves key
  knowledge but deposits/downloads are otherwise unlinkable only as far as the
  transport provides (Tor onion in that fork).
- **No resumable transfers** and no server-side rate limiting beyond size/budget
  caps yet.
