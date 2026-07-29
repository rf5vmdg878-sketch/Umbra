//! Extern declarations for SymCrypt symbols not yet exposed by the official
//! `symcrypt`/`symcrypt-sys` crates (which are generated from SymCrypt 103.4.2,
//! before ML-KEM shipped). The vendored DLL is v103.11.0 and exports all of
//! these; they resolve against the same `symcrypt.lib` the sys crate links.
//!
//! Signatures transcribed from `_sub_src/symcrypt/inc/symcrypt.h`. On x86_64
//! Windows `SYMCRYPT_CALL` is the default C calling convention and C enums are
//! `int`, so plain `extern "C"` declarations are ABI-correct.

use core::ffi::{c_int, c_void};
use std::sync::Once;

pub type SymCryptErrorCode = c_int;
pub const SYMCRYPT_NO_ERROR: SymCryptErrorCode = 0;

/// Opaque handle to a SYMCRYPT_MLKEMKEY.
pub type PSymCryptMlKemKey = *mut c_void;

// SYMCRYPT_MLKEM_PARAMS
pub const MLKEM_PARAMS_MLKEM768: c_int = 2;

// SYMCRYPT_MLKEMKEY_FORMAT
pub const MLKEMKEY_FORMAT_PRIVATE_SEED: c_int = 1; // d || z, 64 bytes
pub const MLKEMKEY_FORMAT_ENCAPSULATION_KEY: c_int = 3; // 1184 bytes for ML-KEM-768

#[link(name = "symcrypt", kind = "dylib")]
unsafe extern "C" {
    pub fn SymCryptMlKemkeyAllocate(params: c_int) -> PSymCryptMlKemKey;
    pub fn SymCryptMlKemkeyFree(pkMlKemkey: PSymCryptMlKemKey);
    pub fn SymCryptMlKemkeySetValue(
        pbSrc: *const u8,
        cbSrc: usize,
        mlKemkeyFormat: c_int,
        flags: u32,
        pkMlKemkey: PSymCryptMlKemKey,
    ) -> SymCryptErrorCode;
    pub fn SymCryptMlKemkeyGetValue(
        pkMlKemkey: PSymCryptMlKemKey,
        pbDst: *mut u8,
        cbDst: usize,
        mlKemkeyFormat: c_int,
        flags: u32,
    ) -> SymCryptErrorCode;
    pub fn SymCryptMlKemEncapsulate(
        pkMlKemkey: PSymCryptMlKemKey,
        pbAgreedSecret: *mut u8,
        cbAgreedSecret: usize,
        pbCiphertext: *mut u8,
        cbCiphertext: usize,
    ) -> SymCryptErrorCode;
    pub fn SymCryptMlKemDecapsulate(
        pkMlKemkey: PSymCryptMlKemKey,
        pbCiphertext: *const u8,
        cbCiphertext: usize,
        pbAgreedSecret: *mut u8,
        cbAgreedSecret: usize,
    ) -> SymCryptErrorCode;
    pub fn SymCryptShake256(
        pbData: *const u8,
        cbData: usize,
        pbResult: *mut u8,
        cbResult: usize,
    );
}

/// The `symcrypt` wrapper crate calls `SymCryptModuleInit` lazily inside its own
/// entry points, but our direct FFI calls need the module initialized too.
/// Idempotent and thread-safe; version constants come from the pinned sys crate
/// (requesting API 103 minor 4 is valid against the newer 103.11 DLL).
pub fn ensure_init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| unsafe {
        symcrypt_sys::SymCryptModuleInit(
            symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
            symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
        );
    });
}
