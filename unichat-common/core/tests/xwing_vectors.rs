//! Known-answer tests for the SymCrypt-backed X-Wing implementation against
//! the official test vectors from draft-connolly-cfrg-xwing-kem (the same
//! vectors the RustCrypto x-wing crate ships).
//!
//! Encapsulation is inherently randomized through SymCrypt's DRBG, so the
//! deterministic checks are key expansion (seed -> public key) and
//! decapsulation (seed, ct -> shared secret). Randomized encapsulation is
//! covered by the cross-implementation tests in `interop.rs`.

use serde::Deserialize;
use zeroize::Zeroizing;

use unichat_core::crypto::xwing::XWingPrivate;

#[derive(Deserialize)]
struct Vector {
    seed: String,
    ss: String,
    pk: String,
    ct: String,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(include_str!("xwing-test-vectors.json")).unwrap()
}

#[test]
fn keygen_matches_official_vectors() {
    for (i, v) in vectors().iter().enumerate() {
        let seed_bytes: [u8; 32] = hex::decode(&v.seed).unwrap().try_into().unwrap();
        let seed = Zeroizing::new(seed_bytes);
        let key = XWingPrivate::from_seed(&seed).unwrap();
        assert_eq!(
            hex::encode(key.public_key_bytes()),
            v.pk,
            "public key mismatch on vector {i}"
        );
    }
}

#[test]
fn decapsulation_matches_official_vectors() {
    for (i, v) in vectors().iter().enumerate() {
        let seed_bytes: [u8; 32] = hex::decode(&v.seed).unwrap().try_into().unwrap();
        let seed = Zeroizing::new(seed_bytes);
        let key = XWingPrivate::from_seed(&seed).unwrap();
        let ct: [u8; 1120] = hex::decode(&v.ct).unwrap().try_into().unwrap();
        let ss = key.decapsulate(&ct).unwrap();
        assert_eq!(
            hex::encode(ss.as_ref()),
            v.ss,
            "shared secret mismatch on vector {i}"
        );
    }
}
