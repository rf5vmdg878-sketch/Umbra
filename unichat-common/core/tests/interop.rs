//! Cross-implementation interop: Microsoft SymCrypt backend vs the RustCrypto
//! `x-wing` crate. Both directions must agree — this exercises the randomized
//! encapsulation paths that the deterministic KATs cannot.

use zeroize::Zeroizing;

use unichat_core::crypto::xwing::{XWingPrivate, XWingPublic};
use x_wing::{Decapsulate, Decapsulator, Encapsulate, KeyExport};

#[test]
fn symcrypt_encapsulates_rustcrypto_decapsulates() {
    let mut seed_bytes = [0u8; 32];
    unichat_core::crypto::random_bytes(&mut seed_bytes);

    // RustCrypto private key from the seed; SymCrypt sees only the public key.
    let rc_private = x_wing::DecapsulationKey::from(seed_bytes);
    let rc_public_bytes: [u8; 1216] = rc_private.encapsulation_key().to_bytes().into();

    let sc_public = XWingPublic::from_bytes(&rc_public_bytes).unwrap();
    let (ct, ss_symcrypt) = sc_public.encapsulate().unwrap();

    let ss_rustcrypto = rc_private.decapsulate(&ct.into());
    assert_eq!(ss_symcrypt.as_ref(), ss_rustcrypto.as_slice());
}

#[test]
fn rustcrypto_encapsulates_symcrypt_decapsulates() {
    let mut seed_bytes = [0u8; 32];
    unichat_core::crypto::random_bytes(&mut seed_bytes);
    let seed = Zeroizing::new(seed_bytes);

    let sc_private = XWingPrivate::from_seed(&seed).unwrap();

    let rc_public =
        x_wing::EncapsulationKey::try_from(sc_private.public_key_bytes().as_slice()).unwrap();
    let (ct, ss_rustcrypto) = rc_public.encapsulate();

    let ct_bytes: [u8; 1120] = ct.into();
    let ss_symcrypt = sc_private.decapsulate(&ct_bytes).unwrap();
    assert_eq!(ss_symcrypt.as_ref(), ss_rustcrypto.as_slice());
}

#[test]
fn same_seed_same_public_key_across_vendors() {
    let mut seed_bytes = [0u8; 32];
    unichat_core::crypto::random_bytes(&mut seed_bytes);

    let rc = x_wing::DecapsulationKey::from(seed_bytes);
    let rc_pk: [u8; 1216] = rc.encapsulation_key().to_bytes().into();

    let seed = Zeroizing::new(seed_bytes);
    let sc = XWingPrivate::from_seed(&seed).unwrap();
    assert_eq!(sc.public_key_bytes(), &rc_pk);
}
