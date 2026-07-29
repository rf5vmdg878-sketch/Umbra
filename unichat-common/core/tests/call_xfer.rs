//! E2E encrypted media (voice/video), file transfer, and relay-routed calls.

use std::net::{TcpListener, TcpStream};
use std::thread;

use zeroize::Zeroizing;

use unichat_core::call::relay::CallRelay;
use unichat_core::call::{new_call_id, rendezvous, MediaKind, SecureMediaChannel};
use unichat_core::identity::Profile;
use unichat_core::session::{initiator_handshake, responder_handshake};
use unichat_core::transport::tcp::TcpTransport;
use unichat_core::xfer::{recv_file, send_file};

/// A connected TCP pair (client stream, and a thread yielding the server stream).
fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let h = thread::spawn(move || listener.accept().unwrap().0);
    let client = TcpStream::connect(addr).unwrap();
    let server = h.join().unwrap();
    (client, server)
}

#[test]
fn media_channel_audio_and_video_round_trip() {
    let (caller_s, callee_s) = tcp_pair();
    let secret = Zeroizing::new([7u8; 32]);
    let s2 = secret.clone();

    let callee = thread::spawn(move || {
        let mut ch = SecureMediaChannel::new(callee_s, &s2, false).unwrap();
        let a = ch.recv().unwrap().unwrap();
        let v = ch.recv().unwrap().unwrap();
        (a.kind, a.payload, a.seq, v.kind, v.payload)
    });

    let mut caller = SecureMediaChannel::new(caller_s, &secret, true).unwrap();
    caller.send(MediaKind::Audio, 1000, b"opus-audio-frame").unwrap();
    caller.send(MediaKind::Video, 1001, b"vp8-keyframe-bytes").unwrap();

    let (ak, ap, aseq, vk, vp) = callee.join().unwrap();
    assert_eq!(ak, MediaKind::Audio);
    assert_eq!(ap, b"opus-audio-frame");
    assert_eq!(aseq, 0);
    assert_eq!(vk, MediaKind::Video);
    assert_eq!(vp, b"vp8-keyframe-bytes");
}

#[test]
fn media_wrong_secret_fails() {
    let (caller_s, callee_s) = tcp_pair();
    let good = Zeroizing::new([1u8; 32]);
    let bad = Zeroizing::new([2u8; 32]);

    let callee = thread::spawn(move || {
        let mut ch = SecureMediaChannel::new(callee_s, &bad, false).unwrap();
        ch.recv().is_err() // wrong key -> auth failure
    });
    let mut caller = SecureMediaChannel::new(caller_s, &good, true).unwrap();
    let _ = caller.send(MediaKind::Audio, 0, b"secret audio");
    assert!(callee.join().unwrap());
}

#[test]
fn file_transfer_e2e_over_session() {
    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let data: Vec<u8> = (0..(200_000u32)).map(|i| (i % 251) as u8).collect();
    let expect = data.clone();

    let responder = thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let id = bob.identity().unwrap();
        let xw = bob.xwing().unwrap();
        let mut ch = responder_handshake(s, &id, &xw).unwrap();
        recv_file(&mut ch, true).unwrap()
    });

    let s = TcpStream::connect(&addr).unwrap();
    let id = alice.identity().unwrap();
    let xw = alice.xwing().unwrap();
    let mut ch = initiator_handshake(s, &id, &xw).unwrap();
    assert!(send_file(&mut ch, "clip.bin", &data).unwrap());

    let (name, got) = responder.join().unwrap().unwrap();
    assert_eq!(name, "clip.bin");
    assert_eq!(got, expect);
}

/// Spawn a CallRelay TCP server; return its address.
fn spawn_call_relay() -> String {
    let relay = CallRelay::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for c in listener.incoming() {
            if let Ok(c) = c {
                let r = relay.clone();
                thread::spawn(move || {
                    let _ = r.handle_connection(c);
                });
            } else {
                break;
            }
        }
    });
    addr
}

#[test]
fn call_relay_forwards_bytes_both_ways() {
    use std::io::{Read, Write};
    let addr = spawn_call_relay();
    let id = new_call_id();
    let t = TcpTransport;

    // callee connects first and waits for a byte, then replies.
    let a2 = addr.clone();
    let id2 = id;
    let callee = thread::spawn(move || {
        let mut c = rendezvous(&t, &a2, &id2, false).unwrap();
        let mut buf = [0u8; 5];
        c.read_exact(&mut buf).unwrap();
        c.write_all(b"pong").unwrap();
        c.flush().unwrap();
        buf
    });
    thread::sleep(std::time::Duration::from_millis(150));
    let mut caller = rendezvous(&TcpTransport, &addr, &id, true).unwrap();
    caller.write_all(b"hello").unwrap();
    caller.flush().unwrap();
    let mut reply = [0u8; 4];
    caller.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"pong");
    assert_eq!(&callee.join().unwrap(), b"hello");
}

#[test]
fn call_end_to_end_through_relay() {
    // Two peers meet on the untrusted relay, run the PQ session handshake over
    // the relayed pipe, transfer a file, then exchange encrypted media — all
    // without the relay being able to read anything.
    let relay = spawn_call_relay();
    let call_id = new_call_id();

    let alice = Profile::create("alice").unwrap();
    let bob = Profile::create("bob").unwrap();
    let alice_id = alice.identity().unwrap().public_bytes();
    let bob_id = bob.identity().unwrap().public_bytes();

    let relay2 = relay.clone();
    let cid2 = call_id;
    // Callee (Bob): connect as non-caller, be the session responder.
    let callee = thread::spawn(move || {
        let conn = rendezvous(&TcpTransport, &relay2, &cid2, false).unwrap();
        let id = bob.identity().unwrap();
        let xw = bob.xwing().unwrap();
        let mut ch = responder_handshake(conn, &id, &xw).unwrap();
        let peer = *ch.peer_identity();
        // receive a file first
        let (fname, fdata) = recv_file(&mut ch, true).unwrap().unwrap();
        // then switch to media and read one audio + one video frame
        let secret = ch.call_secret().clone();
        let caller = ch.is_initiator();
        let mut media = SecureMediaChannel::new(ch.into_inner(), &secret, caller).unwrap();
        let a = media.recv().unwrap().unwrap();
        let v = media.recv().unwrap().unwrap();
        (peer, fname, fdata, a.payload, v.payload)
    });

    thread::sleep(std::time::Duration::from_millis(150));
    // Caller (Alice): connect as caller, be the session initiator.
    let conn = rendezvous(&TcpTransport, &relay, &call_id, true).unwrap();
    let id = alice.identity().unwrap();
    let xw = alice.xwing().unwrap();
    let mut ch = initiator_handshake(conn, &id, &xw).unwrap();
    assert_eq!(ch.peer_identity(), &bob_id);
    let file = b"secret dossier".to_vec();
    assert!(send_file(&mut ch, "dossier.pdf", &file).unwrap());
    let secret = ch.call_secret().clone();
    let caller = ch.is_initiator();
    let mut media = SecureMediaChannel::new(ch.into_inner(), &secret, caller).unwrap();
    media.send(MediaKind::Audio, 0, b"live-voice").unwrap();
    media.send(MediaKind::Video, 0, b"live-video").unwrap();

    let (peer, fname, fdata, apayload, vpayload) = callee.join().unwrap();
    assert_eq!(peer, alice_id); // Bob authenticated Alice through the relay
    assert_eq!(fname, "dossier.pdf");
    assert_eq!(fdata, file);
    assert_eq!(apayload, b"live-voice");
    assert_eq!(vpayload, b"live-video");
}
