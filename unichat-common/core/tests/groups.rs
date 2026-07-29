//! Phase 5 tests: Cwtch-style untrusted-relay groups.

use std::net::{TcpListener, TcpStream};
use std::thread;

use unichat_core::groups::relay::{fetch, post, GroupRelay};
use unichat_core::groups::{group_open, group_seal, Group};
use unichat_core::identity::Profile;
use unichat_core::transport::tcp::TcpTransport;

#[test]
fn descriptor_round_trip() {
    let g = Group::create("secret-cabal");
    let desc = g.descriptor();
    let g2 = Group::from_descriptor(&desc).unwrap();
    assert_eq!(g2.name, "secret-cabal");
    assert_eq!(g2.group_id(), g.group_id());
    // Same key -> a message sealed by one opens with the other.
    let alice = Profile::create("alice").unwrap();
    let blob = group_seal(&g, &alice.identity().unwrap(), "hi").unwrap();
    assert_eq!(group_open(&g2, &blob).unwrap().body, "hi");
}

#[test]
fn seal_open_authenticated() {
    let g = Group::create("g");
    let alice = Profile::create("alice").unwrap();
    let alice_id = alice.identity().unwrap().public_bytes();
    let blob = group_seal(&g, &alice.identity().unwrap(), "hello group").unwrap();
    let msg = group_open(&g, &blob).unwrap();
    assert_eq!(msg.body, "hello group");
    assert_eq!(msg.sender_id, alice_id); // author authenticated
}

#[test]
fn non_member_cannot_read() {
    let g = Group::create("g");
    let other = Group::create("g"); // different key, same name
    let alice = Profile::create("alice").unwrap();
    let blob = group_seal(&g, &alice.identity().unwrap(), "secret").unwrap();
    assert!(group_open(&other, &blob).is_err());
}

#[test]
fn tampered_group_message_rejected() {
    let g = Group::create("g");
    let alice = Profile::create("alice").unwrap();
    let mut blob = group_seal(&g, &alice.identity().unwrap(), "hello").unwrap();
    let mid = blob.len() / 2;
    blob[mid] ^= 0x01;
    assert!(group_open(&g, &blob).is_err());
}

/// A blob from group A must not be reinterpretable in group B even by a member
/// of both (the group id is bound into the AEAD and the author signature).
#[test]
fn cross_group_replay_rejected() {
    let ga = Group::create("A");
    let alice = Profile::create("alice").unwrap();
    let blob = group_seal(&ga, &alice.identity().unwrap(), "for A").unwrap();
    // Rebuild "the same group id" but different key can't open (non_member),
    // and the real group B (different id+key) certainly can't.
    let gb = Group::create("B");
    assert!(group_open(&gb, &blob).is_err());
}

fn spawn_relay() -> (String, GroupRelay, thread::JoinHandle<()>) {
    let relay = GroupRelay::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let srv = relay.clone();
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
    (addr, relay, handle)
}

#[test]
fn multi_member_relay_round_trip() {
    let (addr, relay, _h) = spawn_relay();
    let t = TcpTransport;

    // One group, three members (share the descriptor).
    let founder = Group::create("dev-team");
    let desc = founder.descriptor();
    let g_alice = Group::from_descriptor(&desc).unwrap();
    let g_bob = Group::from_descriptor(&desc).unwrap();
    let g_carol = Group::from_descriptor(&desc).unwrap();
    let gid = *founder.group_id();

    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let alice_id = alice.identity().unwrap().public_bytes();
    let bob_id = bob.identity().unwrap().public_bytes();

    // Alice and Bob each post a message.
    post(&t, &addr, &gid, &group_seal(&g_alice, &alice.identity().unwrap(), "hi from alice").unwrap()).unwrap();
    post(&t, &addr, &gid, &group_seal(&g_bob, &bob.identity().unwrap(), "hi from bob").unwrap()).unwrap();
    assert_eq!(relay.count(&gid), 2);

    // Carol fetches from cursor 0 and decrypts+verifies both.
    let (blobs, cursor) = fetch(&t, &addr, &gid, 0).unwrap();
    assert_eq!(cursor, 2);
    let mut seen: Vec<([u8; 32], String)> = blobs
        .iter()
        .map(|b| {
            let m = group_open(&g_carol, b).unwrap();
            (m.sender_id, m.body)
        })
        .collect();
    seen.sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(seen[0], (alice_id, "hi from alice".to_string()));
    assert_eq!(seen[1], (bob_id, "hi from bob".to_string()));

    // Incremental fetch from the cursor returns nothing new yet...
    let (none, c2) = fetch(&t, &addr, &gid, cursor).unwrap();
    assert!(none.is_empty());
    assert_eq!(c2, 2);

    // ...until Carol posts, then Alice sees just the new one.
    post(&t, &addr, &gid, &group_seal(&g_carol, &Profile::create("carol").unwrap().identity().unwrap(), "hi from carol").unwrap()).unwrap();
    let (newmsgs, c3) = fetch(&t, &addr, &gid, cursor).unwrap();
    assert_eq!(newmsgs.len(), 1);
    assert_eq!(c3, 3);
    assert_eq!(group_open(&g_alice, &newmsgs[0]).unwrap().body, "hi from carol");
}

#[test]
fn relay_cannot_read_and_isolates_groups() {
    let (addr, _relay, _h) = spawn_relay();
    let t = TcpTransport;
    let g1 = Group::create("g1");
    let g2 = Group::create("g2");
    let alice = Profile::create("alice").unwrap();

    let secret = "GROUPSECRETmarker99";
    post(&t, &addr, g1.group_id(), &group_seal(&g1, &alice.identity().unwrap(), secret).unwrap()).unwrap();

    // Fetching g1's ciphertext: it must not contain the plaintext marker.
    let (blobs, _) = fetch(&t, &addr, g1.group_id(), 0).unwrap();
    assert_eq!(blobs.len(), 1);
    assert!(blobs[0].windows(secret.len()).all(|w| w != secret.as_bytes()));

    // g2 has its own address space and sees nothing from g1.
    let (g2msgs, _) = fetch(&t, &addr, g2.group_id(), 0).unwrap();
    assert!(g2msgs.is_empty());
}

#[test]
fn profile_stores_groups() {
    let mut alice = Profile::create("alice").unwrap();
    let g = Group::create("myteam");
    alice.add_group(g.to_stored()).unwrap();
    assert!(alice.add_group(g.to_stored()).is_err()); // duplicate name
    let stored = alice.group("myteam").unwrap();
    let restored = Group::from_stored(stored).unwrap();
    assert_eq!(restored.group_id(), g.group_id());
    // Round-trip a message through the restored group.
    let blob = group_seal(&g, &alice.identity().unwrap(), "x").unwrap();
    assert_eq!(group_open(&restored, &blob).unwrap().body, "x");
    assert!(alice.remove_group("myteam"));
    assert!(alice.group("myteam").is_none());
}
