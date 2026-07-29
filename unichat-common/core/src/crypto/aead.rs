//! AES-256-GCM (SymCrypt) with strict counter-nonce discipline.
//!
//! Nonces are 96-bit counters (`0x00000000 || u64-le counter`), never random
//! and never reused: every key in this codebase is derived freshly per
//! envelope/session via HKDF from a fresh KEM encapsulation, and each record
//! index is used exactly once per key. [`AeadKey::seal`]/[`open`] take the
//! counter explicitly so callers cannot accidentally reuse one — sequence
//! enforcement lives in the envelope layer.

use symcrypt::cipher::BlockCipherType;
use symcrypt::gcm::GcmExpandedKey;
use zeroize::Zeroizing;

use super::{CryptoError, Result};

pub const KEY_SIZE: usize = 32;
pub const TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;

pub struct AeadKey {
    inner: GcmExpandedKey,
}

fn nonce_from_counter(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

impl AeadKey {
    pub fn new(key: &Zeroizing<[u8; KEY_SIZE]>) -> Result<Self> {
        Ok(Self {
            inner: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock)?,
        })
    }

    /// Encrypt `buf` in place and append the 16-byte tag.
    pub fn seal(&self, counter: u64, aad: &[u8], buf: &mut Vec<u8>) {
        let nonce = nonce_from_counter(counter);
        let mut tag = [0u8; TAG_SIZE];
        self.inner.encrypt_in_place(&nonce, aad, buf, &mut tag);
        buf.extend_from_slice(&tag);
    }

    /// Verify the trailing tag and decrypt in place; on success `buf` holds the
    /// plaintext. On failure `buf` is cleared — callers never see partial or
    /// unauthenticated plaintext.
    pub fn open(&self, counter: u64, aad: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        if buf.len() < TAG_SIZE {
            buf.clear();
            return Err(CryptoError::AuthFailed);
        }
        let nonce = nonce_from_counter(counter);
        let ct_len = buf.len() - TAG_SIZE;
        let tag: [u8; TAG_SIZE] = buf[ct_len..].try_into().unwrap();
        buf.truncate(ct_len);
        match self.inner.decrypt_in_place(&nonce, aad, buf, &tag) {
            Ok(()) => Ok(()),
            Err(_) => {
                // SymCrypt has already wiped the buffer contents on auth
                // failure per its GCM contract, but be explicit.
                buf.iter_mut().for_each(|b| *b = 0);
                buf.clear();
                Err(CryptoError::AuthFailed)
            }
        }
    }
}
