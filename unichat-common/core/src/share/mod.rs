//! Ephemeral file sharing (Phase 6) — OnionShare's feature.
//!
//! Two modes, both protected by a random **share key** (OnionShare's private
//! key / client-authorization analog) and both keeping content sealed so the
//! carrier — and, in receive mode, the host until it decrypts — sees only
//! ciphertext:
//!
//! - **Send** ([`Share`]): host a file for a bounded number of downloads
//!   (default one — OnionShare's auto-stop). A downloader must prove knowledge
//!   of the share key (challenge-response) before the sealed content is
//!   released; the file is encrypted under a key derived from the share key, so
//!   only holders of the descriptor can read it.
//! - **Receive** ([`ReceiveShare`]): an anonymous dropbox. Uploaders prove the
//!   receive token, then push content sealed under the receive key; the host
//!   stores opaque blobs (never executing them) and decrypts on demand.
//!
//! The share/receive **descriptor** (`unichat-share-v1:` /
//! `unichat-receive-v1:`) is the capability — hand it to the intended party
//! over a secure channel. Networking lives in [`host`] and runs over any
//! [`crate::transport`] (LAN TCP or a Tor onion service).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zeroize::Zeroizing;

use crate::crypto::aead::AeadKey;
use crate::crypto::kdf::hkdf_sha256_32;
use crate::crypto::{CryptoError, Result};

pub mod host;

pub const SHARE_ID_SIZE: usize = 16;
pub const SHARE_KEY_SIZE: usize = 32;
pub const SEND_PREFIX: &str = "unichat-share-v1:";
pub const RECEIVE_PREFIX: &str = "unichat-receive-v1:";
const CONTENT_INFO: &[u8] = b"unichat-share-content-v1";
const CONTENT_SALT_SIZE: usize = 32;
const MAX_FILENAME: usize = 1024;

fn gen_id_key() -> ([u8; SHARE_ID_SIZE], Zeroizing<[u8; SHARE_KEY_SIZE]>) {
    let mut id = [0u8; SHARE_ID_SIZE];
    crate::crypto::random_bytes(&mut id);
    let mut key = Zeroizing::new([0u8; SHARE_KEY_SIZE]);
    crate::crypto::random_bytes(key.as_mut());
    (id, key)
}

/// Encrypt `(filename, data)` under a key derived from `share_key`, bound to
/// `share_id`. Whole-file (in memory); large-file streaming is future work.
pub fn seal_content(
    share_key: &[u8; SHARE_KEY_SIZE],
    share_id: &[u8; SHARE_ID_SIZE],
    filename: &str,
    data: &[u8],
) -> Result<Vec<u8>> {
    let fname = filename.as_bytes();
    if fname.len() > MAX_FILENAME {
        return Err(CryptoError::Protocol("share filename too long"));
    }
    let mut salt = [0u8; CONTENT_SALT_SIZE];
    crate::crypto::random_bytes(&mut salt);
    let key = hkdf_sha256_32(share_key, &salt, CONTENT_INFO)?;
    let aead = AeadKey::new(&key)?;

    let mut inner = Vec::with_capacity(4 + fname.len() + data.len());
    inner.extend_from_slice(&(fname.len() as u32).to_le_bytes());
    inner.extend_from_slice(fname);
    inner.extend_from_slice(data);
    aead.seal(0, share_id, &mut inner); // aad = share_id; appends GCM tag

    let mut blob = Vec::with_capacity(CONTENT_SALT_SIZE + inner.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&inner);
    Ok(blob)
}

/// Reverse of [`seal_content`].
pub fn open_content(
    share_key: &[u8; SHARE_KEY_SIZE],
    share_id: &[u8; SHARE_ID_SIZE],
    blob: &[u8],
) -> Result<(String, Vec<u8>)> {
    if blob.len() < CONTENT_SALT_SIZE + 4 + 16 {
        return Err(CryptoError::Malformed("share content too short"));
    }
    let salt: [u8; CONTENT_SALT_SIZE] = blob[..CONTENT_SALT_SIZE].try_into().unwrap();
    let mut ct = blob[CONTENT_SALT_SIZE..].to_vec();
    let key = hkdf_sha256_32(share_key, &salt, CONTENT_INFO)?;
    AeadKey::new(&key)?.open(0, share_id, &mut ct)?;

    if ct.len() < 4 {
        return Err(CryptoError::Malformed("share content truncated"));
    }
    let fname_len = u32::from_le_bytes(ct[0..4].try_into().unwrap()) as usize;
    if ct.len() < 4 + fname_len {
        return Err(CryptoError::Malformed("share filename truncated"));
    }
    let filename = String::from_utf8(ct[4..4 + fname_len].to_vec())
        .map_err(|_| CryptoError::Malformed("share filename not UTF-8"))?;
    let data = ct[4 + fname_len..].to_vec();
    Ok((filename, data))
}

fn encode_descriptor(
    prefix: &str,
    label: &str,
    id: &[u8; SHARE_ID_SIZE],
    key: &[u8; SHARE_KEY_SIZE],
    size: u64,
) -> String {
    let l = label.as_bytes();
    let mut raw = Vec::with_capacity(2 + l.len() + SHARE_ID_SIZE + SHARE_KEY_SIZE + 8);
    raw.extend_from_slice(&(l.len() as u16).to_le_bytes());
    raw.extend_from_slice(l);
    raw.extend_from_slice(id);
    raw.extend_from_slice(key);
    raw.extend_from_slice(&size.to_le_bytes());
    format!("{prefix}{}", B64.encode(&raw))
}

fn decode_descriptor(
    prefix: &str,
    text: &str,
) -> Result<(String, [u8; SHARE_ID_SIZE], Zeroizing<[u8; SHARE_KEY_SIZE]>, u64)> {
    let body = text
        .trim()
        .strip_prefix(prefix)
        .ok_or(CryptoError::InvalidKey("wrong share descriptor prefix"))?;
    let raw = B64
        .decode(body.trim())
        .map_err(|_| CryptoError::InvalidKey("share descriptor not base64"))?;
    if raw.len() < 2 {
        return Err(CryptoError::InvalidKey("share descriptor too short"));
    }
    let l = u16::from_le_bytes(raw[0..2].try_into().unwrap()) as usize;
    let want = 2 + l + SHARE_ID_SIZE + SHARE_KEY_SIZE + 8;
    if raw.len() != want {
        return Err(CryptoError::InvalidKey("share descriptor wrong length"));
    }
    let label = String::from_utf8(raw[2..2 + l].to_vec())
        .map_err(|_| CryptoError::InvalidKey("share label not UTF-8"))?;
    let mut o = 2 + l;
    let id: [u8; SHARE_ID_SIZE] = raw[o..o + SHARE_ID_SIZE].try_into().unwrap();
    o += SHARE_ID_SIZE;
    let mut key = Zeroizing::new([0u8; SHARE_KEY_SIZE]);
    key.copy_from_slice(&raw[o..o + SHARE_KEY_SIZE]);
    o += SHARE_KEY_SIZE;
    let size = u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
    Ok((label, id, key, size))
}

/// A file staged for sharing: id + key + the sealed content.
pub struct Share {
    id: [u8; SHARE_ID_SIZE],
    key: Zeroizing<[u8; SHARE_KEY_SIZE]>,
    pub filename: String,
    pub size: u64,
    sealed: Vec<u8>,
}

impl Share {
    pub fn create(filename: &str, data: &[u8]) -> Result<Self> {
        let (id, key) = gen_id_key();
        let sealed = seal_content(&key, &id, filename, data)?;
        Ok(Self {
            id,
            key,
            filename: filename.to_string(),
            size: data.len() as u64,
            sealed,
        })
    }

    pub fn id(&self) -> &[u8; SHARE_ID_SIZE] {
        &self.id
    }
    pub fn key(&self) -> &[u8; SHARE_KEY_SIZE] {
        &self.key
    }
    pub fn sealed(&self) -> &[u8] {
        &self.sealed
    }

    /// The capability to give a downloader.
    pub fn descriptor(&self) -> String {
        encode_descriptor(SEND_PREFIX, &self.filename, &self.id, &self.key, self.size)
    }
}

/// The recipient-side capability for a download.
pub struct ShareRef {
    pub id: [u8; SHARE_ID_SIZE],
    pub key: Zeroizing<[u8; SHARE_KEY_SIZE]>,
    pub filename: String,
    pub size: u64,
}

impl ShareRef {
    pub fn from_descriptor(text: &str) -> Result<Self> {
        let (filename, id, key, size) = decode_descriptor(SEND_PREFIX, text)?;
        Ok(Self {
            id,
            key,
            filename,
            size,
        })
    }
}

/// A receive-mode dropbox capability.
pub struct ReceiveShare {
    id: [u8; SHARE_ID_SIZE],
    key: Zeroizing<[u8; SHARE_KEY_SIZE]>,
    pub label: String,
}

impl ReceiveShare {
    pub fn create(label: &str) -> Self {
        let (id, key) = gen_id_key();
        Self {
            id,
            key,
            label: label.to_string(),
        }
    }

    pub fn id(&self) -> &[u8; SHARE_ID_SIZE] {
        &self.id
    }
    pub fn key(&self) -> &[u8; SHARE_KEY_SIZE] {
        &self.key
    }

    /// The capability to give an uploader.
    pub fn descriptor(&self) -> String {
        encode_descriptor(RECEIVE_PREFIX, &self.label, &self.id, &self.key, 0)
    }
}

/// The uploader-side capability for a receive dropbox.
pub struct ReceiveRef {
    pub id: [u8; SHARE_ID_SIZE],
    pub key: Zeroizing<[u8; SHARE_KEY_SIZE]>,
    pub label: String,
}

impl ReceiveRef {
    pub fn from_descriptor(text: &str) -> Result<Self> {
        let (label, id, key, _size) = decode_descriptor(RECEIVE_PREFIX, text)?;
        Ok(Self { id, key, label })
    }
}
