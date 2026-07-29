//! Store-and-forward sync (Phase 4) — Briar's offline-delivery feature.
//!
//! The Phase 3 session gives *synchronous* chat: both peers online at once.
//! Real messengers must also deliver when peers are *never* online together.
//! Briar solves this with an untrusted store-and-forward **mailbox**; this
//! module is the post-quantum analogue.
//!
//! # Offline sealed messages
//!
//! A message is sealed to the recipient's **long-term X-Wing key** (from their
//! contact bundle) with the Phase 1 `.usealed` envelope — post-quantum
//! confidential and integrity-protected, and openable later without any live
//! handshake. Because there is no session to authenticate the sender, the
//! sender also **signs** `SHA3-256(domain ‖ recipient_id ‖ envelope)` with its
//! Ed25519 identity key and attaches its identity. The recipient verifies the
//! signature, decrypts, and confirms the sender is a known contact.
//!
//! # Untrusted mailbox
//!
//! [`mailbox`] is a store-and-forward node addressed by the **owner's Ed25519
//! identity public key** (Briar's model: the mailbox knows its owner but
//! nothing else). It stores opaque sealed blobs it cannot read, learns nothing
//! about senders (who connect anonymously — over Tor in that fork), and only
//! releases an owner's blobs after a **challenge-response proof** that the
//! collector holds the owner's identity key. It runs over any
//! [`crate::transport`], so the same mailbox works on LAN or as an onion
//! service.

use std::io::Cursor;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::envelope::{seal, Metadata, Opener};
use crate::crypto::xwing::XWingPublic;
use crate::crypto::{CryptoError, Result};
use crate::identity::{verify_detached, Identity, Profile};

pub mod mailbox;

const OFFLINE_DOMAIN: &[u8] = b"unichat-offline-msg-v1\0";

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(p);
    }
    symcrypt::hash::sha3_256(&buf)
}

#[derive(Serialize, Deserialize)]
struct SealedMessage {
    v: u8,
    sender_id: String,
    /// base64 of a random 16-byte message id, authenticated by `sig` — lets the
    /// receiver dedup replays from a malicious mailbox.
    id: String,
    envelope: String,
    sig: String,
}

/// Seal `plaintext` for a recipient, authenticated by the sender's identity.
/// Returns an opaque blob to hand to a mailbox. `recipient_id` is the
/// recipient's Ed25519 identity public key; `recipient_xwing` their long-term
/// X-Wing public key (both from their contact bundle).
pub fn seal_message(
    sender: &Identity,
    recipient_id: &[u8; 32],
    recipient_xwing: &XWingPublic,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let meta = Metadata {
        filename: "message".into(),
        mime: "text/plain".into(),
        size: plaintext.len() as u64,
    };
    let mut envelope = Vec::new();
    seal(recipient_xwing, &meta, &mut Cursor::new(plaintext), &mut envelope)?;

    let mut id = [0u8; 16];
    crate::crypto::random_bytes(&mut id);
    let digest = sha3(&[OFFLINE_DOMAIN, recipient_id, &id, &envelope]);
    let sig = sender.sign_detached(&digest);

    let msg = SealedMessage {
        v: 1,
        sender_id: B64.encode(sender.public_bytes()),
        id: B64.encode(id),
        envelope: B64.encode(&envelope),
        sig: B64.encode(sig),
    };
    serde_json::to_vec(&msg).map_err(|_| CryptoError::Protocol("offline message serialization failed"))
}

/// An opened offline message.
pub struct OpenedMessage {
    /// The sender's authenticated Ed25519 identity public key. The caller must
    /// still confirm this is a known/approved contact before trusting it.
    pub sender_id: [u8; 32],
    /// Authenticated random message id — dedup replays with it.
    pub id: [u8; 16],
    pub plaintext: Vec<u8>,
}

/// Verify and decrypt an offline message blob with the recipient's profile.
pub fn open_message(recipient: &Profile, blob: &[u8]) -> Result<OpenedMessage> {
    let msg: SealedMessage =
        serde_json::from_slice(blob).map_err(|_| CryptoError::Malformed("malformed offline message"))?;
    if msg.v != 1 {
        return Err(CryptoError::UnsupportedFormat);
    }
    let sender_id: [u8; 32] = B64
        .decode(&msg.sender_id)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(CryptoError::Malformed("bad sender id"))?;
    let envelope = B64
        .decode(&msg.envelope)
        .map_err(|_| CryptoError::Malformed("bad envelope"))?;
    let sig: [u8; 64] = B64
        .decode(&msg.sig)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(CryptoError::Malformed("bad signature"))?;
    let id: [u8; 16] = B64
        .decode(&msg.id)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(CryptoError::Malformed("bad message id"))?;

    let my_id = recipient.identity()?.public_bytes();
    let digest = sha3(&[OFFLINE_DOMAIN, &my_id, &id, &envelope]);
    if !verify_detached(&sender_id, &digest, &sig) {
        return Err(CryptoError::PeerAuth("offline message signature invalid"));
    }

    let key = recipient.xwing()?;
    let opener = Opener::new(&key, Cursor::new(&envelope))?;
    let mut plaintext = Vec::new();
    opener.copy_to(&mut plaintext)?;

    Ok(OpenedMessage {
        sender_id,
        id,
        plaintext,
    })
}
