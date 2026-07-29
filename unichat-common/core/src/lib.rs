//! unichat-core — engine library for the unified secure communications suite.
//!
//! Phase 1 exposes the cryptographic core and the `.usealed` envelope format.
//! All primitives are provided by Microsoft SymCrypt (ML-KEM-768, X25519,
//! AES-256-GCM, SHA3-256, SHAKE-256, HKDF-SHA-256, DRBG) except Argon2id,
//! which SymCrypt does not implement and comes from the RustCrypto `argon2`
//! crate (RFC 9106).

pub mod call;
pub mod crypto;
pub mod groups;
pub mod identity;
pub mod integrity;
pub mod session;
pub mod share;
pub mod storage;
pub mod sync;
pub mod transport;
pub mod xfer;
