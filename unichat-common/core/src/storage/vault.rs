//! Opaque encrypted object vault.
//!
//! A vault is a directory of independently-encrypted objects addressed by a
//! logical *label* (e.g. `"profile"`, `"history"`, `"tor-state"`). Nothing about
//! the label — or what the object is — appears on disk: the on-disk filename is
//! a keyed pseudonym `HKDF(master_key, label)` and the contents are AES-256-GCM.
//! An observer with filesystem access learns only that some encrypted objects
//! exist, their sizes, and their count — never their names or contents.
//!
//! The master key comes from the profile envelope ([`super::UnlockedStore`]), so
//! the vault holds no key material of its own; every function takes `&mk`.
//!
//! Object file: `obj_salt(32) || AES-256-GCM(nonce 0, aad = name tag)` where the
//! per-object key is `HKDF(mk, obj_salt, "unichat-vault-obj-v1")`. The AAD binds
//! the ciphertext to its label's name tag, so object files can't be swapped
//! between labels without detection.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::aead::AeadKey;
use crate::crypto::kdf::hkdf_sha256_32;
use crate::crypto::{CryptoError, Result};

const NAME_INFO: &[u8] = b"unichat-vault-name-v1";
const OBJ_INFO: &[u8] = b"unichat-vault-obj-v1";
const OBJ_SALT: usize = 32;
/// Guard against a corrupt/hostile length making us allocate wildly.
const MAX_OBJECT: usize = 256 * 1024 * 1024;

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// The 32-byte keyed name tag for `label` (also the AAD for its object).
fn name_tag(mk: &[u8; 32], label: &str) -> Result<[u8; 32]> {
    let tag = hkdf_sha256_32(mk, label.as_bytes(), NAME_INFO)?;
    Ok(*tag)
}

/// On-disk path of `label`'s object within `dir` — an opaque keyed pseudonym.
pub fn object_path(dir: &Path, mk: &[u8; 32], label: &str) -> Result<PathBuf> {
    let tag = name_tag(mk, label)?;
    Ok(dir.join(to_hex(&tag)))
}

/// Encrypt `plaintext` and store it under `label` (atomic temp-file + rename).
pub fn put_object(dir: &Path, mk: &[u8; 32], label: &str, plaintext: &[u8]) -> Result<()> {
    let tag = name_tag(mk, label)?;
    let path = dir.join(to_hex(&tag));

    let mut obj_salt = [0u8; OBJ_SALT];
    crate::crypto::random_bytes(&mut obj_salt);
    let obj_key = hkdf_sha256_32(mk, &obj_salt, OBJ_INFO)?;

    let mut sealed = plaintext.to_vec();
    AeadKey::new(&obj_key)?.seal(0, &tag, &mut sealed); // appends tag

    let mut out = Vec::with_capacity(OBJ_SALT + sealed.len());
    out.extend_from_slice(&obj_salt);
    out.extend_from_slice(&sealed);

    let tmp = path.with_extension("tmp");
    let result = (|| -> Result<()> {
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&out)?;
            f.sync_all()?; // durability: data on disk before the rename
        }
        // rename atomically replaces the destination on Windows + Unix; no
        // pre-remove (that risked losing the object on a mid-write crash).
        std::fs::rename(&tmp, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Fetch and decrypt `label`, or `None` if the object doesn't exist.
pub fn get_object(dir: &Path, mk: &[u8; 32], label: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let path = object_path(dir, mk, label)?;
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CryptoError::Io(e)),
    };
    if data.len() < OBJ_SALT + 16 {
        return Err(CryptoError::Malformed("vault object truncated"));
    }
    if data.len() - OBJ_SALT > MAX_OBJECT {
        return Err(CryptoError::Malformed("vault object implausibly large"));
    }
    let obj_salt: [u8; OBJ_SALT] = data[..OBJ_SALT].try_into().unwrap();
    let tag = name_tag(mk, label)?;
    let obj_key = hkdf_sha256_32(mk, &obj_salt, OBJ_INFO)?;
    let mut body = Zeroizing::new(data[OBJ_SALT..].to_vec());
    AeadKey::new(&obj_key)?.open(0, &tag, &mut body)?;
    Ok(Some(body))
}

/// Delete `label`'s object if present (no error if already absent).
pub fn remove_object(dir: &Path, mk: &[u8; 32], label: &str) -> Result<()> {
    let path = object_path(dir, mk, label)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CryptoError::Io(e)),
    }
}
