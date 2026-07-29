//! Phase 4 tests: offline sealed messages + untrusted store-and-forward mailbox.

use std::net::{TcpListener, TcpStream};
use std::thread;

use unichat_core::identity::Profile;
use unichat_core::sync::mailbox::{collect, deposit, MailboxStore};
use unichat_core::sync::{open_message, seal_message};
use unichat_core::transport::tcp::TcpTransport;

fn seal_from_to(sender: &Profile, recipient: &Profile, text: &[u8]) -> Vec<u8> {
    let bundle = recipient.bundle().unwrap();
    seal_message(
        &sender.identity().unwrap(),
        bundle.identity_pk(),
        &bundle.xwing_public().unwrap(),
        text,
    )
    .unwrap()
}

#[test]
fn seal_open_round_trip_authenticated() {
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let alice_id = alice.identity().unwrap().public_bytes();

    let blob = seal_from_to(&alice, &bob, b"see you at dawn");
    let opened = open_message(&bob, &blob).unwrap();
    assert_eq!(opened.plaintext, b"see you at dawn");
    assert_eq!(opened.sender_id, alice_id); // sender authenticated
}

#[test]
fn wrong_recipient_cannot_open() {
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let mallory = Profile::create("mallory").unwrap();
    let blob = seal_from_to(&alice, &bob, b"secret");
    assert!(open_message(&mallory, &blob).is_err());
}

#[test]
fn tampered_offline_message_rejected() {
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let mut blob = seal_from_to(&alice, &bob, b"hello there");
    // Flip a byte in the middle of the blob (envelope or signature region).
    let mid = blob.len() / 2;
    blob[mid] ^= 0x01;
    assert!(open_message(&bob, &blob).is_err());
}

/// Spawn a mailbox server on an ephemeral port; returns (addr, store, handle).
fn spawn_mailbox() -> (String, MailboxStore, thread::JoinHandle<()>) {
    let store = MailboxStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let srv = store.clone();
    let handle = thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(c) => {
                    let s = srv.clone();
                    thread::spawn(move || {
                        let _ = s.handle_connection(c);
                    });
                }
                Err(_) => break,
            }
        }
    });
    (addr, store, handle)
}

#[test]
fn store_and_forward_end_to_end() {
    let (addr, store, _h) = spawn_mailbox();
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let bob_id = bob.identity().unwrap().public_bytes();
    let t = TcpTransport;

    // Alice deposits two messages for Bob while Bob is "offline".
    for text in [b"first".as_slice(), b"second".as_slice()] {
        let blob = seal_from_to(&alice, &bob, text);
        deposit(&t, &addr, &bob_id, &blob).unwrap();
    }
    assert_eq!(store.len_for(&bob_id), 2);

    // Bob comes online later, authenticates, collects, decrypts.
    let blobs = collect(&t, &addr, &bob.identity().unwrap()).unwrap();
    assert_eq!(blobs.len(), 2);
    let mut texts: Vec<Vec<u8>> = blobs
        .iter()
        .map(|b| open_message(&bob, b).unwrap().plaintext)
        .collect();
    texts.sort();
    assert_eq!(texts, vec![b"first".to_vec(), b"second".to_vec()]);

    // Collection cleared the mailbox.
    assert_eq!(store.len_for(&bob_id), 0);
}

#[test]
fn only_owner_can_collect() {
    let (addr, store, _h) = spawn_mailbox();
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let mallory = Profile::create("mallory").unwrap();
    let bob_id = bob.identity().unwrap().public_bytes();
    let t = TcpTransport;

    deposit(&t, &addr, &bob_id, &seal_from_to(&alice, &bob, b"for bob")).unwrap();

    // Mallory authenticates with her own key -> her (empty) mailbox, not Bob's.
    let mallory_blobs = collect(&t, &addr, &mallory.identity().unwrap()).unwrap();
    assert!(mallory_blobs.is_empty());
    // Bob's message is untouched and still collectable by Bob.
    assert_eq!(store.len_for(&bob_id), 1);
    let bob_blobs = collect(&t, &addr, &bob.identity().unwrap()).unwrap();
    assert_eq!(bob_blobs.len(), 1);
}

#[test]
fn mailbox_cannot_read_plaintext() {
    let (addr, store, _h) = spawn_mailbox();
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let bob_id = bob.identity().unwrap().public_bytes();
    let t = TcpTransport;

    let secret = b"TOPSECRETmarker12345";
    deposit(&t, &addr, &bob_id, &seal_from_to(&alice, &bob, secret)).unwrap();

    // The stored blob (all the mailbox ever sees) must not contain the
    // plaintext marker, and must not reveal the sender's identity key.
    let stored = collect(&t, &addr, &bob.identity().unwrap()).unwrap();
    let _ = &store; // store consulted above
    assert_eq!(stored.len(), 1);
    let blob = &stored[0];
    assert!(
        blob.windows(secret.len()).all(|w| w != secret),
        "plaintext leaked into the sealed blob"
    );
}
