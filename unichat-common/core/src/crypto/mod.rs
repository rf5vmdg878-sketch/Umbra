//! Cryptographic core.
//!
//! Layout:
//! - [`ffi`]     — extern declarations for SymCrypt symbols the official
//!                 `symcrypt` crate does not yet expose (ML-KEM, SHAKE-256, DRBG).
//! - [`mlkem`]   — safe wrapper over SymCrypt ML-KEM-768 (FIPS 203).
//! - [`xwing`]   — X-Wing hybrid KEM (ML-KEM-768 + X25519), draft-connolly-cfrg-xwing-kem-06,
//!                 composed exclusively from SymCrypt primitives.
//! - [`aead`]    — AES-256-GCM with counter nonces (SymCrypt).
//! - [`kdf`]     — HKDF-SHA-256 (SymCrypt) and Argon2id (RustCrypto).
//! - [`envelope`]— the `.usealed` streaming file-encryption format.
//! - [`keyfile`] — serialization of public/secret key files.

pub mod aead;
pub mod envelope;
pub mod ffi;
pub mod kdf;
pub mod keyfile;
pub mod mlkem;
pub mod xwing;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("SymCrypt error code {0:#x} during {1}")]
    SymCrypt(i32, &'static str),
    #[error("SymCrypt error: {0}")]
    SymCryptWrapper(symcrypt::errors::SymCryptError),
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("invalid key material: {0}")]
    InvalidKey(&'static str),
    #[error("envelope is malformed: {0}")]
    Malformed(&'static str),
    #[error("authentication failed — data is corrupt or was tampered with")]
    AuthFailed,
    #[error("unsupported version or magic")]
    UnsupportedFormat,
    #[error("wrong passphrase or corrupted key file")]
    WrongPassphrase,
    #[error("handshake failed: {0}")]
    Handshake(&'static str),
    #[error("peer authentication failed: {0}")]
    PeerAuth(&'static str),
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<symcrypt::errors::SymCryptError> for CryptoError {
    fn from(e: symcrypt::errors::SymCryptError) -> Self {
        CryptoError::SymCryptWrapper(e)
    }
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Fill `buf` with random bytes from SymCrypt's FIPS DRBG.
pub fn random_bytes(buf: &mut [u8]) {
    ffi::ensure_init();
    unsafe {
        symcrypt_sys::SymCryptRandom(buf.as_mut_ptr(), buf.len() as symcrypt_sys::SIZE_T);
    }
}
