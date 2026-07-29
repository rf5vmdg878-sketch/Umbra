//! Safe wrapper over Microsoft SymCrypt's ML-KEM-768 (FIPS 203).
//!
//! Keys live inside SymCrypt-allocated objects; this module never copies raw
//! private key material into Rust-managed memory except the caller-provided
//! 64-byte private seed, which callers are expected to hold in `Zeroizing`.

use zeroize::Zeroizing;

use super::ffi;
use super::{CryptoError, Result};

pub const ENCAPS_KEY_SIZE: usize = 1184;
pub const CIPHERTEXT_SIZE: usize = 1088;
pub const PRIVATE_SEED_SIZE: usize = 64; // d || z per FIPS 203
pub const SHARED_SECRET_SIZE: usize = 32;

/// Owned handle to a SYMCRYPT_MLKEMKEY; freed (and internally wiped by
/// SymCrypt) on drop.
struct KeyHandle(ffi::PSymCryptMlKemKey);

// The underlying SymCrypt key object is not mutated after import, and SymCrypt
// documents its key objects as safe for concurrent read use.
unsafe impl Send for KeyHandle {}
unsafe impl Sync for KeyHandle {}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        unsafe { ffi::SymCryptMlKemkeyFree(self.0) };
    }
}

fn allocate() -> Result<KeyHandle> {
    ffi::ensure_init();
    let ptr = unsafe { ffi::SymCryptMlKemkeyAllocate(ffi::MLKEM_PARAMS_MLKEM768) };
    if ptr.is_null() {
        return Err(CryptoError::SymCrypt(-1, "MlKemkeyAllocate"));
    }
    Ok(KeyHandle(ptr))
}

fn check(code: ffi::SymCryptErrorCode, what: &'static str) -> Result<()> {
    if code == ffi::SYMCRYPT_NO_ERROR {
        Ok(())
    } else {
        Err(CryptoError::SymCrypt(code, what))
    }
}

/// ML-KEM-768 encapsulation (public) key.
pub struct MlKem768Public(KeyHandle);

impl MlKem768Public {
    pub fn from_bytes(ek: &[u8; ENCAPS_KEY_SIZE]) -> Result<Self> {
        let key = allocate()?;
        check(
            unsafe {
                ffi::SymCryptMlKemkeySetValue(
                    ek.as_ptr(),
                    ek.len(),
                    ffi::MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
                    0,
                    key.0,
                )
            },
            "MlKemkeySetValue(encapsulation key)",
        )?;
        Ok(Self(key))
    }

    /// Encapsulate to this key using SymCrypt's DRBG for randomness.
    pub fn encapsulate(
        &self,
    ) -> Result<([u8; CIPHERTEXT_SIZE], Zeroizing<[u8; SHARED_SECRET_SIZE]>)> {
        let mut ct = [0u8; CIPHERTEXT_SIZE];
        let mut ss = Zeroizing::new([0u8; SHARED_SECRET_SIZE]);
        check(
            unsafe {
                ffi::SymCryptMlKemEncapsulate(
                    self.0 .0,
                    ss.as_mut_ptr(),
                    ss.len(),
                    ct.as_mut_ptr(),
                    ct.len(),
                )
            },
            "MlKemEncapsulate",
        )?;
        Ok((ct, ss))
    }
}

/// ML-KEM-768 full keypair, imported from the 64-byte private seed (d || z).
pub struct MlKem768Private(KeyHandle);

impl MlKem768Private {
    pub fn from_seed(seed: &[u8; PRIVATE_SEED_SIZE]) -> Result<Self> {
        let key = allocate()?;
        check(
            unsafe {
                ffi::SymCryptMlKemkeySetValue(
                    seed.as_ptr(),
                    seed.len(),
                    ffi::MLKEMKEY_FORMAT_PRIVATE_SEED,
                    0,
                    key.0,
                )
            },
            "MlKemkeySetValue(private seed)",
        )?;
        Ok(Self(key))
    }

    /// Export the public (encapsulation) key bytes.
    pub fn encapsulation_key_bytes(&self) -> Result<[u8; ENCAPS_KEY_SIZE]> {
        let mut ek = [0u8; ENCAPS_KEY_SIZE];
        check(
            unsafe {
                ffi::SymCryptMlKemkeyGetValue(
                    self.0 .0,
                    ek.as_mut_ptr(),
                    ek.len(),
                    ffi::MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
                    0,
                )
            },
            "MlKemkeyGetValue(encapsulation key)",
        )?;
        Ok(ek)
    }

    pub fn decapsulate(
        &self,
        ct: &[u8; CIPHERTEXT_SIZE],
    ) -> Result<Zeroizing<[u8; SHARED_SECRET_SIZE]>> {
        let mut ss = Zeroizing::new([0u8; SHARED_SECRET_SIZE]);
        check(
            unsafe {
                ffi::SymCryptMlKemDecapsulate(
                    self.0 .0,
                    ct.as_ptr(),
                    ct.len(),
                    ss.as_mut_ptr(),
                    ss.len(),
                )
            },
            "MlKemDecapsulate",
        )?;
        Ok(ss)
    }
}

/// One-shot SHAKE-256 with arbitrary output length.
pub fn shake256(data: &[u8], out: &mut [u8]) {
    ffi::ensure_init();
    unsafe { ffi::SymCryptShake256(data.as_ptr(), data.len(), out.as_mut_ptr(), out.len()) };
}
