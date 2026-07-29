//! Phase 2 tests: identity bundles, contacts, and the encrypted profile store.

use std::io::Cursor;

use zeroize::Zeroizing;

use unichat_core::crypto::envelope::{seal, Metadata, Opener};
use unichat_core::crypto::CryptoError;
use unichat_core::identity::{ContactState, KeyBundle, Profile};
use unichat_core::storage::UnlockedStore;

fn pass(s: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.as_bytes().to_vec())
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("unichat-phase2-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn bundle_round_trip_and_verify() {
    let profile = Profile::create("alice").unwrap();
    let text = profile.bundle().unwrap().encode();
    let decoded = KeyBundle::decode(&text).unwrap();
    assert_eq!(decoded.fingerprint(), profile.fingerprint().unwrap());
}

#[test]
fn tampered_bundle_rejected() {
    let profile = Profile::create("alice").unwrap();
    let bundle = profile.bundle().unwrap();
    let text = bundle.encode();
    let raw_start = "unichat-bundle-v1:".len();

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let mut raw = B64.decode(&text[raw_start..]).unwrap();
    // Tamper in each region: identity pk, X-Wing pk, signature.
    for off in [5usize, 100, 32 + 1216 + 10] {
        let mut bad = raw.clone();
        bad[off] ^= 0x01;
        let bad_text = format!("unichat-bundle-v1:{}", B64.encode(&bad));
        assert!(
            KeyBundle::decode(&bad_text).is_err(),
            "tampered bundle at raw offset {off} was accepted"
        );
    }
    // Sanity: untampered round-trips.
    raw[0] ^= 0;
    assert!(KeyBundle::decode(&text).is_ok());
}

#[test]
fn store_create_open_round_trip_with_contacts() {
    let path = temp_path("roundtrip");
    let mut profile = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    profile.add_contact("bob", &bob.bundle().unwrap()).unwrap();

    let store = UnlockedStore::create(&path, &pass("pw1"), &profile).unwrap();
    drop(store);

    let (_store, restored) = UnlockedStore::open(&path, &pass("pw1")).unwrap();
    assert_eq!(restored.display_name, "alice");
    assert_eq!(restored.contacts.len(), 1);
    assert_eq!(restored.contacts[0].alias, "bob");
    assert_eq!(restored.contacts[0].state, ContactState::Approved);
    assert_eq!(
        restored.contacts[0].fingerprint().unwrap(),
        bob.fingerprint().unwrap()
    );
    // Keys survive the round trip.
    assert_eq!(
        restored.fingerprint().unwrap(),
        profile.fingerprint().unwrap()
    );
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn wrong_passphrase_rejected() {
    let path = temp_path("wrongpass");
    let profile = Profile::create("alice").unwrap();
    UnlockedStore::create(&path, &pass("right"), &profile).unwrap();
    assert!(matches!(
        UnlockedStore::open(&path, &pass("wrong")),
        Err(CryptoError::WrongPassphrase)
    ));
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn store_tampering_rejected() {
    let path = temp_path("tamper");
    let profile = Profile::create("alice").unwrap();
    UnlockedStore::create(&path, &pass("pw"), &profile).unwrap();
    let good = std::fs::read(&path).unwrap();

    // Flip a byte in every structural region: salt, params, mk wrap,
    // body salt, body start, body end.
    for off in [10usize, 26, 40, 90, 120, good.len() - 1] {
        let mut bad = good.clone();
        bad[off] ^= 0x01;
        std::fs::write(&path, &bad).unwrap();
        assert!(
            UnlockedStore::open(&path, &pass("pw")).is_err(),
            "tampering at offset {off} was accepted"
        );
    }
    std::fs::write(&path, &good).unwrap();
    assert!(UnlockedStore::open(&path, &pass("pw")).is_ok());
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn change_passphrase_keeps_data() {
    let path = temp_path("changepass");
    let mut profile = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    profile.add_contact("bob", &bob.bundle().unwrap()).unwrap();

    let (mut store, profile) = {
        UnlockedStore::create(&path, &pass("old"), &profile).unwrap();
        UnlockedStore::open(&path, &pass("old")).unwrap()
    };
    store.change_passphrase(&pass("new"), &profile).unwrap();

    assert!(matches!(
        UnlockedStore::open(&path, &pass("old")),
        Err(CryptoError::WrongPassphrase)
    ));
    let (_s, restored) = UnlockedStore::open(&path, &pass("new")).unwrap();
    assert_eq!(restored.contacts.len(), 1);
    assert_eq!(
        restored.fingerprint().unwrap(),
        profile.fingerprint().unwrap()
    );
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn duplicate_and_self_contacts_rejected() {
    let mut alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    alice.add_contact("bob", &bob.bundle().unwrap()).unwrap();
    assert!(alice.add_contact("bob", &bob.bundle().unwrap()).is_err());
    let own = alice.bundle().unwrap();
    assert!(alice.add_contact("me", &own).is_err());
}

/// End-to-end: a contact stored in the profile can receive a sealed envelope
/// that the contact's own profile keys decrypt.
#[test]
fn contact_keys_work_with_envelope() {
    let mut alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    alice.add_contact("bob", &bob.bundle().unwrap()).unwrap();

    let data = b"hello bob, love alice".to_vec();
    let meta = Metadata {
        filename: "note.txt".into(),
        mime: String::new(),
        size: data.len() as u64,
    };
    let recipient = alice.contact("bob").unwrap().xwing_public().unwrap();
    let mut sealed = Vec::new();
    seal(&recipient, &meta, &mut Cursor::new(&data), &mut sealed).unwrap();

    let bob_key = bob.xwing().unwrap();
    let opener = Opener::new(&bob_key, Cursor::new(&sealed)).unwrap();
    let mut out = Vec::new();
    opener.copy_to(&mut out).unwrap();
    assert_eq!(out, data);
}
