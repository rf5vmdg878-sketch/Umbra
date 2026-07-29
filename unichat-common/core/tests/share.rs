//! Phase 6 tests: ephemeral file shares (send/download) + receive dropbox.

use std::net::{TcpListener, TcpStream};
use std::thread;

use unichat_core::share::host::{download, upload, ShareHost};
use unichat_core::share::{
    open_content, seal_content, ReceiveRef, ReceiveShare, Share, ShareRef,
};
use unichat_core::transport::tcp::TcpTransport;

#[test]
fn content_seal_open_round_trip() {
    let share = Share::create("report.pdf", b"top secret contents").unwrap();
    let (name, data) = open_content(share.key(), share.id(), share.sealed()).unwrap();
    assert_eq!(name, "report.pdf");
    assert_eq!(data, b"top secret contents");
}

#[test]
fn content_wrong_key_and_tamper_fail() {
    let share = Share::create("f", b"data").unwrap();
    let wrong = [9u8; 32];
    assert!(open_content(&wrong, share.id(), share.sealed()).is_err());

    let mut blob = seal_content(share.key(), share.id(), "f", b"data").unwrap();
    let mid = blob.len() / 2;
    blob[mid] ^= 1;
    assert!(open_content(share.key(), share.id(), &blob).is_err());
}

#[test]
fn descriptor_round_trips() {
    let s = Share::create("a.bin", b"xyz").unwrap();
    let r = ShareRef::from_descriptor(&s.descriptor()).unwrap();
    assert_eq!(r.id, *s.id());
    assert_eq!(r.filename, "a.bin");
    assert_eq!(r.size, 3);

    let rx = ReceiveShare::create("dropbox");
    let rr = ReceiveRef::from_descriptor(&rx.descriptor()).unwrap();
    assert_eq!(rr.id, *rx.id());
    assert_eq!(rr.label, "dropbox");
    // A send descriptor must not parse as a receive descriptor.
    assert!(ReceiveRef::from_descriptor(&s.descriptor()).is_err());
}

fn spawn_host() -> (String, ShareHost, thread::JoinHandle<()>) {
    let host = ShareHost::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let srv = host.clone();
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
    (addr, host, handle)
}

#[test]
fn one_shot_download_then_auto_stop() {
    let (addr, host, _h) = spawn_host();
    let t = TcpTransport;
    let share = Share::create("secret.txt", b"the eagle lands at noon").unwrap();
    let id = *share.id();
    let desc = share.descriptor();
    host.host_send(&share, 1); // one download only

    // First download succeeds.
    let sref = ShareRef::from_descriptor(&desc).unwrap();
    let (name, data) = download(&t, &addr, &sref).unwrap();
    assert_eq!(name, "secret.txt");
    assert_eq!(data, b"the eagle lands at noon");
    assert_eq!(host.send_remaining(&id), 0);

    // Second download is refused (auto-stopped).
    let sref2 = ShareRef::from_descriptor(&desc).unwrap();
    assert!(download(&t, &addr, &sref2).is_err());
}

#[test]
fn wrong_token_cannot_download() {
    let (addr, host, _h) = spawn_host();
    let t = TcpTransport;
    let share = Share::create("f", b"data").unwrap();
    host.host_send(&share, 5);

    // A ShareRef with the right id but a wrong key must fail the challenge.
    let mut forged = ShareRef::from_descriptor(&share.descriptor()).unwrap();
    forged.key = zeroize::Zeroizing::new([0u8; 32]);
    assert!(download(&t, &addr, &forged).is_err());
    // The legitimate download budget is untouched.
    assert_eq!(host.send_remaining(share.id()), 5);
}

#[test]
fn multi_download_budget() {
    let (addr, host, _h) = spawn_host();
    let t = TcpTransport;
    let share = Share::create("f", b"data").unwrap();
    let desc = share.descriptor();
    host.host_send(&share, 3);
    for _ in 0..3 {
        assert!(download(&t, &addr, &ShareRef::from_descriptor(&desc).unwrap()).is_ok());
    }
    assert!(download(&t, &addr, &ShareRef::from_descriptor(&desc).unwrap()).is_err());
}

#[test]
fn receive_dropbox_round_trip() {
    let (addr, host, _h) = spawn_host();
    let t = TcpTransport;
    let dropbox = ReceiveShare::create("tips");
    let id = *dropbox.id();
    host.host_receive(dropbox.id(), dropbox.key());
    let desc = dropbox.descriptor();

    // Two uploaders push files with the receive token.
    let up = ReceiveRef::from_descriptor(&desc).unwrap();
    upload(&t, &addr, &up, "leak1.txt", b"documents A").unwrap();
    let up2 = ReceiveRef::from_descriptor(&desc).unwrap();
    upload(&t, &addr, &up2, "leak2.txt", b"documents B").unwrap();

    // The host decrypts the stored (sealed) uploads.
    let blobs = host.received(&id);
    assert_eq!(blobs.len(), 2);
    let mut got: Vec<(String, Vec<u8>)> = blobs
        .iter()
        .map(|b| open_content(dropbox.key(), &id, b).unwrap())
        .collect();
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(got[0], ("leak1.txt".to_string(), b"documents A".to_vec()));
    assert_eq!(got[1], ("leak2.txt".to_string(), b"documents B".to_vec()));
}

#[test]
fn wrong_token_cannot_upload() {
    let (addr, host, _h) = spawn_host();
    let t = TcpTransport;
    let dropbox = ReceiveShare::create("tips");
    host.host_receive(dropbox.id(), dropbox.key());

    let mut forged = ReceiveRef::from_descriptor(&dropbox.descriptor()).unwrap();
    forged.key = zeroize::Zeroizing::new([7u8; 32]);
    assert!(upload(&t, &addr, &forged, "x", b"y").is_err());
    assert!(host.received(dropbox.id()).is_empty());
}

#[test]
fn host_isolates_send_and_receive_ids() {
    let (addr, host, _h) = spawn_host();
    let t = TcpTransport;
    let share = Share::create("f", b"data").unwrap();
    host.host_send(&share, 1);

    // Trying to UPLOAD to a send-share id must fail (not a dropbox).
    let as_receive = ReceiveRef {
        id: *share.id(),
        key: zeroize::Zeroizing::new(*share.key()),
        label: String::new(),
    };
    assert!(upload(&t, &addr, &as_receive, "x", b"y").is_err());
    // And downloading a non-existent share id fails.
    let ghost = ShareRef {
        id: [0u8; 16],
        key: zeroize::Zeroizing::new([0u8; 32]),
        filename: String::new(),
        size: 0,
    };
    assert!(download(&t, &addr, &ghost).is_err());
}
