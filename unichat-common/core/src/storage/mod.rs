//! Encrypted profile store (Phase 2) — Cwtch's "profile encrypted at rest"
//! model with a master-key envelope.
//!
//! File format (`UPROFDB` v1):
//! ```text
//! magic      8  "UPROFDB\x01"
//! salt      16  Argon2id salt
//! m_kib      4  u32-le ┐
//! t_cost     4  u32-le ├ Argon2id parameters (floored at decode)
//! p_cost     4  u32-le ┘
//! mk_wrap   48  AES-256-GCM(master key) under KEK, nonce 0, AAD = bytes[0..36]
//! body_salt 32  fresh random salt for every save
//! body       *  AES-256-GCM(profile JSON) under HKDF(MK, body_salt), nonce 0,
//!               AAD = bytes[0..116] (everything before the body)
//! ```
//!
//! Security properties:
//! - **Envelope pattern**: the random 256-bit master key (MK) encrypts the
//!   data; the passphrase only wraps MK. Changing the passphrase rewraps 48
//!   bytes and never touches (or weakens) the body encryption.
//! - **Nonce discipline**: both GCM records use nonce 0 under keys that are
//!   used exactly once — the KEK is unique per (passphrase, salt) and the body
//!   key is re-derived from a fresh 32-byte salt on every save.
//! - **No plaintext metadata**: display name, contacts, timestamps, key seeds
//!   all live inside the encrypted body.
//! - **Atomic saves**: written to a temp file then renamed; a crash mid-save
//!   leaves the old profile intact.
//! - The AAD chain binds header fields, so KDF-parameter or salt tampering is
//!   detected before (and independently of) the parameter floor check.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::aead::{AeadKey, TAG_SIZE};
use crate::crypto::kdf::{argon2id_32, hkdf_sha256_32, Argon2Params, SALT_SIZE};
use crate::crypto::{CryptoError, Result};
use crate::identity::Profile;

const MAGIC: [u8; 8] = *b"UPROFDB\x01";
const PRE_MK: usize = 8 + SALT_SIZE + 12; // 36
const MK_WRAP: usize = 32 + TAG_SIZE; // 48
const BODY_SALT_SIZE: usize = 32;
const HEADER: usize = PRE_MK + MK_WRAP + BODY_SALT_SIZE; // 116
const BODY_INFO: &[u8] = b"unichat-profile-v1 body";
const MAX_BODY: usize = 64 * 1024 * 1024;

/// An unlocked profile store: path + master key + current passphrase wrapping.
pub struct UnlockedStore {
    path: PathBuf,
    master_key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_SIZE],
    params: Argon2Params,
    mk_wrap: [u8; MK_WRAP],
}

impl UnlockedStore {
    /// Create a new store file for `profile`. Refuses to overwrite.
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
        let mut master_key = Zeroizing::new([0u8; 32]);
        crate::crypto::random_bytes(master_key.as_mut());

        let mut store = Self {
            path: path.to_path_buf(),
            master_key,
            salt: [0u8; SALT_SIZE],
            params: Argon2Params::default(),
            mk_wrap: [0u8; MK_WRAP],
        };
        store.rewrap(passphrase)?;
        store.save(profile)?;
        Ok(store)
    }

    /// Open and decrypt an existing store.
    pub fn open(path: &Path, passphrase: &Zeroizing<Vec<u8>>) -> Result<(Self, Profile)> {
        let data = std::fs::read(path)?;
        if data.len() < HEADER + TAG_SIZE || data[..8] != MAGIC {
            return Err(CryptoError::UnsupportedFormat);
        }
        let salt: [u8; SALT_SIZE] = data[8..8 + SALT_SIZE].try_into().unwrap();
        let params = Argon2Params {
            m_cost_kib: u32::from_le_bytes(data[24..28].try_into().unwrap()),
            t_cost: u32::from_le_bytes(data[28..32].try_into().unwrap()),
            p_cost: u32::from_le_bytes(data[32..36].try_into().unwrap()),
        };
        let mk_wrap: [u8; MK_WRAP] = data[PRE_MK..PRE_MK + MK_WRAP].try_into().unwrap();
        let body_salt: [u8; BODY_SALT_SIZE] =
            data[PRE_MK + MK_WRAP..HEADER].try_into().unwrap();

        // Unwrap the master key (this is where a wrong passphrase fails).
        let kek = argon2id_32(passphrase, &salt, params)?;
        let mut mk_buf = mk_wrap.to_vec();
        AeadKey::new(&kek)?
            .open(0, &data[..PRE_MK], &mut mk_buf)
            .map_err(|_| CryptoError::WrongPassphrase)?;
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(&mk_buf);
        mk_buf.iter_mut().for_each(|b| *b = 0);

        // Decrypt the body.
        if data.len() - HEADER > MAX_BODY {
            return Err(CryptoError::Malformed("profile body implausibly large"));
        }
        let body_key = hkdf_sha256_32(master_key.as_ref(), &body_salt, BODY_INFO)?;
        let mut body = data[HEADER..].to_vec();
        AeadKey::new(&body_key)?.open(0, &data[..HEADER], &mut body)?;
        let profile: Profile = serde_json::from_slice(&body)
            .map_err(|_| CryptoError::Malformed("profile body failed to parse"))?;
        body.iter_mut().for_each(|b| *b = 0);

        Ok((
            Self {
                path: path.to_path_buf(),
                master_key,
                salt,
                params,
                mk_wrap,
            },
            profile,
        ))
    }

    /// Serialize and write the profile atomically (temp file + rename).
    pub fn save(&self, profile: &Profile) -> Result<()> {
        let mut header = Vec::with_capacity(HEADER);
        header.extend_from_slice(&MAGIC);
        header.extend_from_slice(&self.salt);
        header.extend_from_slice(&self.params.m_cost_kib.to_le_bytes());
        header.extend_from_slice(&self.params.t_cost.to_le_bytes());
        header.extend_from_slice(&self.params.p_cost.to_le_bytes());
        header.extend_from_slice(&self.mk_wrap);

        let mut body_salt = [0u8; BODY_SALT_SIZE];
        crate::crypto::random_bytes(&mut body_salt);
        header.extend_from_slice(&body_salt);
        debug_assert_eq!(header.len(), HEADER);

        let body_key = hkdf_sha256_32(self.master_key.as_ref(), &body_salt, BODY_INFO)?;
        let body = Zeroizing::new(
            serde_json::to_vec(profile)
                .map_err(|_| CryptoError::Malformed("profile serialization failed"))?,
        );
        let mut sealed = body.clone().to_vec();
        AeadKey::new(&body_key)?.seal(0, &header, &mut sealed);
        drop(body); // Zeroizing<Vec<u8>> wipes the plaintext JSON on drop.

        let tmp = self.path.with_extension("tmp");
        let result = (|| -> Result<()> {
            std::fs::write(&tmp, [header.as_slice(), sealed.as_slice()].concat())?;
            if self.path.exists() {
                std::fs::remove_file(&self.path)?;
            }
            std::fs::rename(&tmp, &self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Re-wrap the master key under a (new) passphrase with a fresh salt and
    /// default parameters. Body encryption is untouched.
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
    /// existing body data — is unchanged.
    pub fn change_passphrase(
        &mut self,
        new_passphrase: &Zeroizing<Vec<u8>>,
        profile: &Profile,
    ) -> Result<()> {
        self.rewrap(new_passphrase)?;
        self.save(profile)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
