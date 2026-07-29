//! Phase 3 session tests: mutually authenticated handshake, encrypted chat,
//! knock/approve, and man-in-the-middle rejection — all over TCP loopback.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use unichat_core::identity::Profile;
use unichat_core::session::{
    initiator_handshake, responder_handshake, AppMsg, SecureChannel,
};

/// Spawn a responder on an ephemeral port; return (address, join handle) where
/// the handle yields the responder's authenticated view.
fn spawn_responder<F>(profile: Profile, run: F) -> (String, thread::JoinHandle<()>)
where
    F: FnOnce(SecureChannel<TcpStream>) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let identity = profile.identity().unwrap();
        let xwing = profile.xwing().unwrap();
        let ch = responder_handshake(stream, &identity, &xwing).unwrap();
        run(ch);
    });
    (addr, handle)
}

#[test]
fn handshake_and_bidirectional_chat() {
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let alice_id = alice.identity().unwrap().public_bytes();
    let bob_id = bob.identity().unwrap().public_bytes();

    let (addr, responder) = spawn_responder(bob, move |mut ch| {
        // Responder is Bob. Peer must authenticate as Alice.
        assert_eq!(ch.peer_identity(), &alice_id);
        // Receive a chat, ack it, then send one back.
        match ch.recv().unwrap().unwrap() {
            AppMsg::Chat { id, text } => {
                assert_eq!(text, "hi bob");
                ch.send(&AppMsg::ChatAck { id }).unwrap();
            }
            other => panic!("unexpected: {other:?}"),
        }
        ch.send(&AppMsg::Chat {
            id: 1,
            text: "hi alice".into(),
        })
        .unwrap();
        assert!(matches!(ch.recv().unwrap(), Some(AppMsg::ChatAck { id: 1 })));
    });

    let stream = TcpStream::connect(&addr).unwrap();
    let identity = alice.identity().unwrap();
    let xwing = alice.xwing().unwrap();
    let mut ch = initiator_handshake(stream, &identity, &xwing).unwrap();
    // Initiator authenticated the responder as Bob.
    assert_eq!(ch.peer_identity(), &bob_id);

    ch.send(&AppMsg::Chat {
        id: 42,
        text: "hi bob".into(),
    })
    .unwrap();
    assert!(matches!(ch.recv().unwrap(), Some(AppMsg::ChatAck { id: 42 })));
    match ch.recv().unwrap().unwrap() {
        AppMsg::Chat { id, text } => {
            assert_eq!(text, "hi alice");
            ch.send(&AppMsg::ChatAck { id }).unwrap();
        }
        other => panic!("unexpected: {other:?}"),
    }
    responder.join().unwrap();
}

#[test]
fn knock_then_approve() {
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let alice_id = alice.identity().unwrap().public_bytes();
    let alice_fp = alice.fingerprint().unwrap();
    let alice_bundle = alice.bundle().unwrap().encode();
    let bob_bundle = bob.bundle().unwrap().encode();

    let (addr, responder) = spawn_responder(bob, move |mut ch| {
        // Bob does not know Alice: expect a contact request first.
        match ch.recv().unwrap().unwrap() {
            AppMsg::ContactRequest {
                nickname, bundle, ..
            } => {
                assert_eq!(nickname, "Alice");
                assert_eq!(ch.peer_identity(), &alice_id);
                // The bundle must verify AND match the authenticated identity.
                let verified = ch.verify_peer_bundle(&bundle).unwrap();
                assert_eq!(verified.fingerprint(), alice_fp);
                ch.send(&AppMsg::ContactResponse {
                    accepted: true,
                    bundle: Some(bob_bundle.clone()),
                })
                .unwrap();
            }
            other => panic!("expected knock, got {other:?}"),
        }
        // Now approved: normal chat.
        assert!(matches!(ch.recv().unwrap(), Some(AppMsg::Chat { .. })));
    });

    let stream = TcpStream::connect(&addr).unwrap();
    let identity = alice.identity().unwrap();
    let xwing = alice.xwing().unwrap();
    let mut ch = initiator_handshake(stream, &identity, &xwing).unwrap();
    ch.send(&AppMsg::ContactRequest {
        nickname: "Alice".into(),
        text: "hi, add me?".into(),
        bundle: alice_bundle,
    })
    .unwrap();
    match ch.recv().unwrap().unwrap() {
        AppMsg::ContactResponse {
            accepted: true,
            bundle: Some(b),
        } => {
            // Initiator can also verify + persist the responder as a contact.
            ch.verify_peer_bundle(&b).unwrap();
        }
        other => panic!("expected acceptance with bundle, got {other:?}"),
    }
    ch.send(&AppMsg::Chat {
        id: 1,
        text: "thanks!".into(),
    })
    .unwrap();
    responder.join().unwrap();
}

#[test]
fn knock_then_reject() {
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();

    let alice_bundle = alice.bundle().unwrap().encode();
    let (addr, responder) = spawn_responder(bob, move |mut ch| {
        match ch.recv().unwrap().unwrap() {
            AppMsg::ContactRequest { .. } => {
                ch.send(&AppMsg::ContactResponse {
                    accepted: false,
                    bundle: None,
                })
                .unwrap();
            }
            other => panic!("expected knock, got {other:?}"),
        }
    });

    let stream = TcpStream::connect(&addr).unwrap();
    let identity = alice.identity().unwrap();
    let xwing = alice.xwing().unwrap();
    let mut ch = initiator_handshake(stream, &identity, &xwing).unwrap();
    ch.send(&AppMsg::ContactRequest {
        nickname: "Alice".into(),
        text: "add me".into(),
        bundle: alice_bundle,
    })
    .unwrap();
    assert!(matches!(
        ch.recv().unwrap(),
        Some(AppMsg::ContactResponse {
            accepted: false,
            ..
        })
    ));
    responder.join().unwrap();
}

/// A knock that carries a validly-signed bundle for a DIFFERENT identity than
/// the one authenticated by the handshake must be rejected.
#[test]
fn knock_with_mismatched_bundle_rejected() {
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let mallory = Profile::create("mallory").unwrap();
    // Alice tries to pass off Mallory's (validly-signed) bundle as her own.
    let mallory_bundle = mallory.bundle().unwrap().encode();

    let (addr, responder) = spawn_responder(bob, move |mut ch| {
        match ch.recv().unwrap().unwrap() {
            AppMsg::ContactRequest { bundle, .. } => {
                // Signature is valid, but identity != authenticated peer.
                assert!(ch.verify_peer_bundle(&bundle).is_err());
                ch.send(&AppMsg::ContactResponse {
                    accepted: false,
                    bundle: None,
                })
                .unwrap();
            }
            other => panic!("expected knock, got {other:?}"),
        }
    });

    let stream = TcpStream::connect(&addr).unwrap();
    let identity = alice.identity().unwrap();
    let xwing = alice.xwing().unwrap();
    let mut ch = initiator_handshake(stream, &identity, &xwing).unwrap();
    ch.send(&AppMsg::ContactRequest {
        nickname: "Alice".into(),
        text: "add me".into(),
        bundle: mallory_bundle,
    })
    .unwrap();
    let _ = ch.recv();
    responder.join().unwrap();
}

/// A man-in-the-middle that forwards bytes but corrupts the first byte from
/// initiator to responder must break the handshake (transcript/magic binding).
#[test]
fn mitm_tampering_breaks_handshake() {
    let bob = Profile::create("bob").unwrap();

    // Real responder.
    let real = TcpListener::bind("127.0.0.1:0").unwrap();
    let real_addr = real.local_addr().unwrap().to_string();
    let responder = thread::spawn(move || {
        let (stream, _) = real.accept().unwrap();
        let identity = bob.identity().unwrap();
        let xwing = bob.xwing().unwrap();
        responder_handshake(stream, &identity, &xwing) // expected to fail
    });

    // Tampering proxy.
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let (mut client, _) = proxy.accept().unwrap();
        let mut upstream = TcpStream::connect(&real_addr).unwrap();
        let mut up2 = upstream.try_clone().unwrap();
        let mut c2 = client.try_clone().unwrap();
        // responder -> client (verbatim). When upstream closes (responder
        // rejected the handshake), shut down the client socket so the
        // initiator sees EOF instead of blocking forever.
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = up2.read(&mut buf) {
                if n == 0 || c2.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            let _ = c2.shutdown(std::net::Shutdown::Both);
        });
        // client -> responder, flipping the very first byte once.
        let mut buf = [0u8; 4096];
        let mut flipped = false;
        while let Ok(n) = client.read(&mut buf) {
            if n == 0 {
                break;
            }
            if !flipped {
                buf[0] ^= 0xff;
                flipped = true;
            }
            if upstream.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });

    let alice = Profile::create("alice").unwrap();
    let stream = TcpStream::connect(&proxy_addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let identity = alice.identity().unwrap();
    let xwing = alice.xwing().unwrap();
    let init_result = initiator_handshake(stream, &identity, &xwing);

    let resp_result = responder.join().unwrap();
    // The responder must reject the corrupted handshake, and the two sides must
    // NOT end up with a shared channel.
    assert!(
        resp_result.is_err(),
        "responder accepted a tampered handshake"
    );
    let _ = init_result; // initiator side also fails or is left dangling
}
