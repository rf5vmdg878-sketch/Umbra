//! Untrusted-relay group messaging (Phase 5) — Cwtch's model.
//!
//! A group is a shared 32-byte symmetric key plus a public 16-byte group id.
//! Members post **authored, encrypted** messages to a *dumb, untrusted* relay
//! ([`relay`]) addressed by the group id. The relay stores and forwards opaque
//! blobs: it cannot read them (no key), does not know authorship (the sender id
//! is *inside* the ciphertext), and enforces no membership — privacy comes from
//! the key, not from access control. Anyone holding the group id can fetch
//! ciphertext; only members holding the key can decrypt.
//!
//! # Per-message crypto
//!
//! Multiple members share one key, so a per-message key is derived from a fresh
//! random 32-byte salt — `msg_key = HKDF-SHA256(group_key, salt,
//! "unichat-group-msg-v1")` — and AES-256-GCM runs with a fixed zero nonce.
//! Because each `msg_key` is unique, nonce reuse is impossible (this sidesteps
//! GCM's 96-bit random-nonce birthday bound with many writers). The plaintext
//! carries the author's Ed25519 identity and a signature over
//! `SHA3-256(domain ‖ group_id ‖ inner)`, so every member can verify *who*
//! wrote each message and that it belongs to *this* group (no cross-group
//! replay). The group id is also the AEAD associated data.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::aead::AeadKey;
use crate::crypto::kdf::hkdf_sha256_32;
use crate::crypto::{CryptoError, Result};
use crate::identity::{verify_detached, Identity, StoredGroup};

pub mod relay;

pub const GROUP_ID_SIZE: usize = 16;
pub const GROUP_KEY_SIZE: usize = 32;
const SALT_SIZE: usize = 32;
pub const DESCRIPTOR_PREFIX: &str = "unichat-group-v1:";
const MSG_INFO: &[u8] = b"unichat-group-msg-v1";
const SIG_DOMAIN: &[u8] = b"unichat-group-author-v1\0";
const MAX_BODY: usize = 64 * 1024;

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(p);
    }
    symcrypt::hash::sha3_256(&buf)
}

/// A group's secret material and identity.
pub struct Group {
    pub name: String,
    group_id: [u8; GROUP_ID_SIZE],
    group_key: Zeroizing<[u8; GROUP_KEY_SIZE]>,
}

impl Group {
    /// Create a brand-new group with random id + key.
    pub fn create(name: &str) -> Self {
        let mut group_id = [0u8; GROUP_ID_SIZE];
        crate::crypto::random_bytes(&mut group_id);
        let mut group_key = Zeroizing::new([0u8; GROUP_KEY_SIZE]);
        crate::crypto::random_bytes(group_key.as_mut());
        Self {
            name: name.to_string(),
            group_id,
            group_key,
        }
    }

    pub fn group_id(&self) -> &[u8; GROUP_ID_SIZE] {
        &self.group_id
    }

    /// A shareable secret invite string. Anyone given this becomes a member, so
    /// deliver it only over an authenticated/sealed channel (Phase 3 chat or a
    /// Phase 4 sealed message).
    pub fn descriptor(&self) -> String {
        let name = self.name.as_bytes();
        let mut raw = Vec::with_capacity(2 + name.len() + GROUP_ID_SIZE + GROUP_KEY_SIZE);
        raw.extend_from_slice(&(name.len() as u16).to_le_bytes());
        raw.extend_from_slice(name);
        raw.extend_from_slice(&self.group_id);
        raw.extend_from_slice(self.group_key.as_ref());
        format!("{}{}", DESCRIPTOR_PREFIX, B64.encode(&raw))
    }

    pub fn from_descriptor(text: &str) -> Result<Self> {
        let body = text
            .trim()
            .strip_prefix(DESCRIPTOR_PREFIX)
            .ok_or(CryptoError::InvalidKey("missing unichat-group-v1 prefix"))?;
        let raw = B64
            .decode(body.trim())
            .map_err(|_| CryptoError::InvalidKey("group descriptor not valid base64"))?;
        if raw.len() < 2 {
            return Err(CryptoError::InvalidKey("group descriptor too short"));
        }
        let name_len = u16::from_le_bytes(raw[0..2].try_into().unwrap()) as usize;
        let want = 2 + name_len + GROUP_ID_SIZE + GROUP_KEY_SIZE;
        if raw.len() != want {
            return Err(CryptoError::InvalidKey("group descriptor has wrong length"));
        }
        let name = String::from_utf8(raw[2..2 + name_len].to_vec())
            .map_err(|_| CryptoError::InvalidKey("group name not UTF-8"))?;
        let mut o = 2 + name_len;
        let group_id: [u8; GROUP_ID_SIZE] = raw[o..o + GROUP_ID_SIZE].try_into().unwrap();
        o += GROUP_ID_SIZE;
        let mut group_key = Zeroizing::new([0u8; GROUP_KEY_SIZE]);
        group_key.copy_from_slice(&raw[o..o + GROUP_KEY_SIZE]);
        Ok(Self {
            name,
            group_id,
            group_key,
        })
    }

    pub fn to_stored(&self) -> StoredGroup {
        StoredGroup {
            name: self.name.clone(),
            group_id_b64: B64.encode(self.group_id),
            group_key_b64: B64.encode(self.group_key.as_ref()),
        }
    }

    pub fn from_stored(s: &StoredGroup) -> Result<Self> {
        let group_id: [u8; GROUP_ID_SIZE] = B64
            .decode(&s.group_id_b64)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(CryptoError::InvalidKey("stored group id corrupt"))?;
        let key_vec = B64
            .decode(&s.group_key_b64)
            .map_err(|_| CryptoError::InvalidKey("stored group key corrupt"))?;
        let key_arr: [u8; GROUP_KEY_SIZE] = key_vec
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("stored group key wrong size"))?;
        Ok(Self {
            name: s.name.clone(),
            group_id,
            group_key: Zeroizing::new(key_arr),
        })
    }

    fn message_key(&self, salt: &[u8; SALT_SIZE]) -> Result<AeadKey> {
        let key = hkdf_sha256_32(self.group_key.as_ref(), salt, MSG_INFO)?;
        AeadKey::new(&key)
    }
}

#[derive(Serialize, Deserialize)]
struct Inner {
    sender: String, // base64 of the author's Ed25519 identity pk
    id: String,     // base64 of a random 16-byte message id (replay/dedup)
    ts: u64,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct Blob {
    v: u8,
    salt: String,
    ct: String,
}

/// A decrypted, author-verified group message.
pub struct GroupMessage {
    /// Authenticated author identity. The caller resolves this to a contact.
    pub sender_id: [u8; 32],
    /// Authenticated random message id — use it to dedup replays (a malicious
    /// relay can re-deliver a valid blob; the id lets the receiver drop it).
    pub id: [u8; 16],
    pub ts: u64,
    pub body: String,
}

/// Author, encrypt, and package a message for the group. The returned bytes are
/// the opaque blob to post to a relay.
pub fn group_seal(group: &Group, author: &Identity, body: &str) -> Result<Vec<u8>> {
    if body.len() > MAX_BODY {
        return Err(CryptoError::Protocol("group message too large"));
    }
    let mut id = [0u8; 16];
    crate::crypto::random_bytes(&mut id);
    let inner = Inner {
        sender: B64.encode(author.public_bytes()),
        id: B64.encode(id),
        ts: now_unix(),
        body: body.to_string(),
    };
    let inner_bytes =
        serde_json::to_vec(&inner).map_err(|_| CryptoError::Protocol("group inner encode"))?;
    let digest = sha3(&[SIG_DOMAIN, &group.group_id, &inner_bytes]);
    let sig = author.sign_detached(&digest);

    // payload = u32-le(inner_len) ‖ inner_bytes ‖ sig(64)
    let mut payload = Vec::with_capacity(4 + inner_bytes.len() + 64);
    payload.extend_from_slice(&(inner_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(&inner_bytes);
    payload.extend_from_slice(&sig);

    let mut salt = [0u8; SALT_SIZE];
    crate::crypto::random_bytes(&mut salt);
    let key = group.message_key(&salt)?;
    key.seal(0, &group.group_id, &mut payload); // aad = group_id; appends GCM tag

    let blob = Blob {
        v: 1,
        salt: B64.encode(salt),
        ct: B64.encode(&payload),
    };
    serde_json::to_vec(&blob).map_err(|_| CryptoError::Protocol("group blob encode"))
}

/// Decrypt and verify a group blob. Returns the message with its authenticated
/// author, or an error if it isn't for this group / fails authentication.
pub fn group_open(group: &Group, blob: &[u8]) -> Result<GroupMessage> {
    let blob: Blob =
        serde_json::from_slice(blob).map_err(|_| CryptoError::Malformed("malformed group blob"))?;
    if blob.v != 1 {
        return Err(CryptoError::UnsupportedFormat);
    }
    let salt: [u8; SALT_SIZE] = B64
        .decode(&blob.salt)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(CryptoError::Malformed("bad group salt"))?;
    let mut payload = B64
        .decode(&blob.ct)
        .map_err(|_| CryptoError::Malformed("bad group ciphertext"))?;

    let key = group.message_key(&salt)?;
    key.open(0, &group.group_id, &mut payload)?; // fails if not our group / tampered

    if payload.len() < 4 + 64 {
        return Err(CryptoError::Malformed("group payload too short"));
    }
    let inner_len = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    if payload.len() != 4 + inner_len + 64 {
        return Err(CryptoError::Malformed("group payload length mismatch"));
    }
    let inner_bytes = &payload[4..4 + inner_len];
    let sig: [u8; 64] = payload[4 + inner_len..].try_into().unwrap();

    let inner: Inner = serde_json::from_slice(inner_bytes)
        .map_err(|_| CryptoError::Malformed("malformed group inner"))?;
    let sender_id: [u8; 32] = B64
        .decode(&inner.sender)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(CryptoError::Malformed("bad author id"))?;

    let digest = sha3(&[SIG_DOMAIN, &group.group_id, inner_bytes]);
    if !verify_detached(&sender_id, &digest, &sig) {
        return Err(CryptoError::PeerAuth("group message author signature invalid"));
    }
    let id: [u8; 16] = B64
        .decode(&inner.id)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(CryptoError::Malformed("bad group message id"))?;

    Ok(GroupMessage {
        sender_id,
        id,
        ts: inner.ts,
        body: inner.body,
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
