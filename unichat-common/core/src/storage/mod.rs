//! Encrypted profile store (Phase 2) — Cwtch's "profile encrypted at rest"
//! model with a master-key envelope, stored in an **opaque object vault** so
//! nothing on disk — not even the filenames — reveals what is stored.
//!
//! On-disk layout (a directory, the "vault"):
//! ```text
//! <vault>/keyring                      the passphrase envelope (anchor)
//! <vault>/<64 hex chars>               profile object  (name = HKDF(MK,"profile"))
//! <vault>/<64 hex chars>               e.g. tor-state, history … (opaque names)
//! ```
//! The anchor is the only fixed name; it holds no plaintext, only the wrapped
//! master key. Every other object's filename is a keyed pseudonym (see
//! [`vault`]) and its contents are AES-256-GCM.
//!
//! Anchor format (`UPROFDB` v1 envelope):
//! ```text
//! magic      8  "UPROFDB\x01"
//! salt      16  Argon2id salt
//! m_kib      4  u32-le ┐
//! t_cost     4  u32-le ├ Argon2id parameters (floored at decode)
//! p_cost     4  u32-le ┘
//! mk_wrap   48  AES-256-GCM(master key) under KEK, nonce 0, AAD = bytes[0..36]
//! ```
//!
//! Security properties:
//! - **Envelope pattern**: a random 256-bit master key (MK) keys every object;
//!   the passphrase only wraps MK. Changing the passphrase rewraps 48 bytes and
//!   never touches (or weakens) any object.
//! - **Nonce discipline**: the MK wrap uses nonce 0 under a KEK unique per
//!   (passphrase, salt); each object uses nonce 0 under a key derived from its
//!   own fresh 32-byte salt.
//! - **No plaintext metadata, including filenames**: display name, contacts,
//!   timestamps, key seeds live inside encrypted objects whose names are opaque.
//! - **Atomic writes**: temp file + rename; a crash mid-write leaves the prior
//!   object intact.
//! - Legacy single-file `UPROFDB` stores are migrated into a vault on first open.

pub mod vault;

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::aead::{AeadKey, TAG_SIZE};
use crate::crypto::kdf::{argon2id_32, hkdf_sha256_32, Argon2Params, SALT_SIZE};
use crate::crypto::{CryptoError, Result};
use crate::identity::Profile;

const MAGIC: [u8; 8] = *b"UPROFDB\x01";
const PRE_MK: usize = 8 + SALT_SIZE + 12; // 36
const MK_WRAP: usize = 32 + TAG_SIZE; // 48
const ANCHOR_LEN: usize = PRE_MK + MK_WRAP; // 84
/// The only fixed filename in a vault: the passphrase envelope. Neutral name —
/// its contents are an opaque encrypted key wrap, revealing nothing.
const ANCHOR: &str = "keyring";
/// Logical label of the profile object (its on-disk name is a keyed pseudonym).
const PROFILE_LABEL: &str = "profile";

// Legacy single-file format (migrated away on first open).
const BODY_SALT_SIZE: usize = 32;
const LEGACY_HEADER: usize = PRE_MK + MK_WRAP + BODY_SALT_SIZE; // 116
const BODY_INFO: &[u8] = b"unichat-profile-v1 body";
const MAX_BODY: usize = 64 * 1024 * 1024;

/// An unlocked profile store: vault directory + master key + passphrase wrapping.
pub struct UnlockedStore {
    dir: PathBuf,
    master_key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_SIZE],
    params: Argon2Params,
    mk_wrap: [u8; MK_WRAP],
}

impl UnlockedStore {
    /// Create a new vault for `profile`. Refuses to overwrite an existing path.
    pub fn create(
        path: &Path,
        passphrase: &Zeroizing<Vec<u8>>,
        profile: &Profile,
    ) -> Result<Self> {
        if path.exists() {
            return Err(CryptoError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists", path.display()),
            )));
        }
        std::fs::create_dir_all(path)?;
        let mut master_key = Zeroizing::new([0u8; 32]);
        crate::crypto::random_bytes(master_key.as_mut());

        let mut store = Self {
            dir: path.to_path_buf(),
            master_key,
            salt: [0u8; SALT_SIZE],
            params: Argon2Params::default(),
            mk_wrap: [0u8; MK_WRAP],
        };
        store.rewrap(passphrase)?;
        store.write_anchor()?;
        store.save(profile)?;
        Ok(store)
    }

    /// Open and decrypt an existing vault. A legacy single-file store at `path`
    /// is transparently migrated into a vault directory first.
    pub fn open(path: &Path, passphrase: &Zeroizing<Vec<u8>>) -> Result<(Self, Profile)> {
        if path.is_file() {
            migrate_legacy(path, passphrase)?;
        }

        let anchor = std::fs::read(path.join(ANCHOR))?;
        if anchor.len() != ANCHOR_LEN || anchor[..8] != MAGIC {
            return Err(CryptoError::UnsupportedFormat);
        }
        let salt: [u8; SALT_SIZE] = anchor[8..8 + SALT_SIZE].try_into().unwrap();
        let params = Argon2Params {
            m_cost_kib: u32::from_le_bytes(anchor[24..28].try_into().unwrap()),
            t_cost: u32::from_le_bytes(anchor[28..32].try_into().unwrap()),
            p_cost: u32::from_le_bytes(anchor[32..36].try_into().unwrap()),
        };
        let mk_wrap: [u8; MK_WRAP] = anchor[PRE_MK..PRE_MK + MK_WRAP].try_into().unwrap();

        // Unwrap the master key (this is where a wrong passphrase fails).
        let kek = argon2id_32(passphrase, &salt, params)?;
        let mut mk_buf = mk_wrap.to_vec();
        AeadKey::new(&kek)?
            .open(0, &anchor[..PRE_MK], &mut mk_buf)
            .map_err(|_| CryptoError::WrongPassphrase)?;
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(&mk_buf);
        mk_buf.iter_mut().for_each(|b| *b = 0);

        let store = Self {
            dir: path.to_path_buf(),
            master_key,
            salt,
            params,
            mk_wrap,
        };

        let body = vault::get_object(&store.dir, &store.master_key, PROFILE_LABEL)?
            .ok_or(CryptoError::Malformed("profile object missing from vault"))?;
        let profile: Profile = serde_json::from_slice(&body)
            .map_err(|_| CryptoError::Malformed("profile body failed to parse"))?;

        Ok((store, profile))
    }

    /// Serialize and write the profile object (encrypted, opaque name, atomic).
    pub fn save(&self, profile: &Profile) -> Result<()> {
        let body = Zeroizing::new(
            serde_json::to_vec(profile)
                .map_err(|_| CryptoError::Malformed("profile serialization failed"))?,
        );
        vault::put_object(&self.dir, &self.master_key, PROFILE_LABEL, &body)
    }

    /// Store an arbitrary encrypted object under `label` (opaque on-disk name).
    /// Used for auxiliary at-rest data (e.g. Tor state, cached history).
    pub fn put_object(&self, label: &str, plaintext: &[u8]) -> Result<()> {
        vault::put_object(&self.dir, &self.master_key, label, plaintext)
    }

    /// Fetch a previously stored object, or `None` if absent.
    pub fn get_object(&self, label: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        vault::get_object(&self.dir, &self.master_key, label)
    }

    /// Delete an object if present.
    pub fn remove_object(&self, label: &str) -> Result<()> {
        vault::remove_object(&self.dir, &self.master_key, label)
    }

    /// Write the passphrase envelope (anchor) atomically.
    fn write_anchor(&self) -> Result<()> {
        let mut anchor = Vec::with_capacity(ANCHOR_LEN);
        anchor.extend_from_slice(&MAGIC);
        anchor.extend_from_slice(&self.salt);
        anchor.extend_from_slice(&self.params.m_cost_kib.to_le_bytes());
        anchor.extend_from_slice(&self.params.t_cost.to_le_bytes());
        anchor.extend_from_slice(&self.params.p_cost.to_le_bytes());
        anchor.extend_from_slice(&self.mk_wrap);
        debug_assert_eq!(anchor.len(), ANCHOR_LEN);

        let path = self.dir.join(ANCHOR);
        let tmp = path.with_extension("tmp");
        let result = (|| -> Result<()> {
            std::fs::write(&tmp, &anchor)?;
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            std::fs::rename(&tmp, &path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Re-wrap the master key under a (new) passphrase with a fresh salt and
    /// default parameters. Object encryption is untouched.
    fn rewrap(&mut self, passphrase: &Zeroizing<Vec<u8>>) -> Result<()> {
        crate::crypto::random_bytes(&mut self.salt);
        self.params = Argon2Params::default();

        let mut pre = Vec::with_capacity(PRE_MK);
        pre.extend_from_slice(&MAGIC);
        pre.extend_from_slice(&self.salt);
        pre.extend_from_slice(&self.params.m_cost_kib.to_le_bytes());
        pre.extend_from_slice(&self.params.t_cost.to_le_bytes());
        pre.extend_from_slice(&self.params.p_cost.to_le_bytes());

        let kek = argon2id_32(passphrase, &self.salt, self.params)?;
        let mut mk_buf = self.master_key.to_vec();
        AeadKey::new(&kek)?.seal(0, &pre, &mut mk_buf);
        self.mk_wrap = mk_buf
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("master key wrap has wrong size"))?;
        Ok(())
    }

    /// Change the passphrase and persist. The master key — and therefore all
    /// objects — is unchanged; only the anchor is rewritten.
    pub fn change_passphrase(
        &mut self,
        new_passphrase: &Zeroizing<Vec<u8>>,
        _profile: &Profile,
    ) -> Result<()> {
        self.rewrap(new_passphrase)?;
        self.write_anchor()
    }

    /// The vault directory backing this store.
    pub fn path(&self) -> &Path {
        &self.dir
    }
}

/// Convert a legacy single-file `UPROFDB` store into a vault directory in place.
/// The old file is decrypted, moved aside as `<name>.legacy.bak`, and its
/// contents re-stored as vault objects under the *same* master key/envelope.
fn migrate_legacy(path: &Path, passphrase: &Zeroizing<Vec<u8>>) -> Result<()> {
    let data = std::fs::read(path)?;
    if data.len() < LEGACY_HEADER + TAG_SIZE || data[..8] != MAGIC {
        return Err(CryptoError::UnsupportedFormat);
    }
    let salt: [u8; SALT_SIZE] = data[8..8 + SALT_SIZE].try_into().unwrap();
    let params = Argon2Params {
        m_cost_kib: u32::from_le_bytes(data[24..28].try_into().unwrap()),
        t_cost: u32::from_le_bytes(data[28..32].try_into().unwrap()),
        p_cost: u32::from_le_bytes(data[32..36].try_into().unwrap()),
    };
    let mk_wrap: [u8; MK_WRAP] = data[PRE_MK..PRE_MK + MK_WRAP].try_into().unwrap();
    let body_salt: [u8; BODY_SALT_SIZE] = data[PRE_MK + MK_WRAP..LEGACY_HEADER].try_into().unwrap();

    let kek = argon2id_32(passphrase, &salt, params)?;
    let mut mk_buf = mk_wrap.to_vec();
    AeadKey::new(&kek)?
        .open(0, &data[..PRE_MK], &mut mk_buf)
        .map_err(|_| CryptoError::WrongPassphrase)?;
    let mut master_key = Zeroizing::new([0u8; 32]);
    master_key.copy_from_slice(&mk_buf);
    mk_buf.iter_mut().for_each(|b| *b = 0);

    if data.len() - LEGACY_HEADER > MAX_BODY {
        return Err(CryptoError::Malformed("profile body implausibly large"));
    }
    let body_key = hkdf_sha256_32(master_key.as_ref(), &body_salt, BODY_INFO)?;
    let mut body = Zeroizing::new(data[LEGACY_HEADER..].to_vec());
    AeadKey::new(&body_key)?.open(0, &data[..LEGACY_HEADER], &mut body)?;

    // Move the old file aside, then create the vault directory at its path.
    let backup = path.with_extension("legacy.bak");
    std::fs::rename(path, &backup)?;
    std::fs::create_dir_all(path)?;

    let store = UnlockedStore {
        dir: path.to_path_buf(),
        master_key,
        salt,
        params,
        mk_wrap,
    };
    store.write_anchor()?;
    vault::put_object(&store.dir, &store.master_key, PROFILE_LABEL, &body)?;
    Ok(())
}
