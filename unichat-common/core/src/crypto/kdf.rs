//! Key derivation.
//!
//! - HKDF-SHA-256 via SymCrypt for all key-from-secret derivations.
//! - Argon2id (RFC 9106) via the RustCrypto `argon2` crate for every
//!   passphrase-derived key. SymCrypt has no memory-hard KDF; a fast KDF over
//!   a human passphrase would be a real weakening, so this is the one
//!   primitive sourced outside Microsoft's library.

use argon2::{Algorithm, Argon2, Params, Version};
use symcrypt::hkdf::hkdf;
use symcrypt::hmac::HmacAlgorithm;
use zeroize::Zeroizing;

use super::{CryptoError, Result};

/// HKDF-SHA-256 -> 32-byte key.
pub fn hkdf_sha256_32(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut vec = hkdf(HmacAlgorithm::HmacSha256, ikm, salt, info, 32)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&vec);
    vec.iter_mut().for_each(|b| *b = 0);
    Ok(out)
}

/// Argon2id parameters, stored alongside every ciphertext they protect so they
/// can be raised in the future without breaking old files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    /// 64 MiB, 3 passes, 4 lanes — at or above the RFC 9106 recommended
    /// baseline for interactive use.
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

/// Floor values below which we refuse to derive (protects against a tampered
/// key file downgrading the KDF to something brute-forceable).
pub const MIN_M_COST_KIB: u32 = 8 * 1024;
pub const MIN_T_COST: u32 = 1;

pub const SALT_SIZE: usize = 16;

/// Argon2id(passphrase, salt) -> 32-byte key.
pub fn argon2id_32(
    passphrase: &[u8],
    salt: &[u8; SALT_SIZE],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    if params.m_cost_kib < MIN_M_COST_KIB || params.t_cost < MIN_T_COST || params.p_cost == 0 {
        return Err(CryptoError::Kdf(
            "Argon2id parameters below security floor".into(),
        ));
    }
    let inner = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, inner);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt.as_ref(), out.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}
