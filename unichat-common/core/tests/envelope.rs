//! Envelope round-trip and tamper-resistance tests.

use std::io::Cursor;

use zeroize::Zeroizing;

use unichat_core::crypto::envelope::{seal, Metadata, Opener, CHUNK_SIZE};
use unichat_core::crypto::keyfile;
use unichat_core::crypto::xwing::XWingPrivate;
use unichat_core::crypto::CryptoError;

fn keypair() -> XWingPrivate {
    XWingPrivate::generate().unwrap()
}

fn seal_bytes(key: &XWingPrivate, name: &str, data: &[u8]) -> Vec<u8> {
    let meta = Metadata {
        filename: name.into(),
        mime: "application/octet-stream".into(),
        size: data.len() as u64,
    };
    let mut out = Vec::new();
    seal(
        &key.public_key().unwrap(),
        &meta,
        &mut Cursor::new(data),
        &mut out,
    )
    .unwrap();
    out
}

fn open_bytes(key: &XWingPrivate, sealed: &[u8]) -> Result<(Metadata, Vec<u8>), CryptoError> {
    let opener = Opener::new(key, Cursor::new(sealed))?;
    let meta = opener.metadata().clone();
    let mut out = Vec::new();
    opener.copy_to(&mut out)?;
    Ok((meta, out))
}

#[test]
fn round_trip_small() {
    let key = keypair();
    let data = b"attack at dawn".to_vec();
    let sealed = seal_bytes(&key, "orders.txt", &data);
    let (meta, plain) = open_bytes(&key, &sealed).unwrap();
    assert_eq!(plain, data);
    assert_eq!(meta.filename, "orders.txt");
    assert_eq!(meta.size, data.len() as u64);
}

#[test]
fn round_trip_empty_file() {
    let key = keypair();
    let sealed = seal_bytes(&key, "empty", b"");
    let (meta, plain) = open_bytes(&key, &sealed).unwrap();
    assert!(plain.is_empty());
    assert_eq!(meta.size, 0);
}

#[test]
fn round_trip_multi_chunk() {
    let key = keypair();
    // Cross several chunk boundaries, including an exact-multiple edge.
    for size in [
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        2 * CHUNK_SIZE + 12345,
    ] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let sealed = seal_bytes(&key, "big.bin", &data);
        let (_, plain) = open_bytes(&key, &sealed).unwrap();
        assert_eq!(plain, data, "size {size}");
    }
}

#[test]
fn wrong_key_fails() {
    let alice = keypair();
    let mallory = keypair();
    let sealed = seal_bytes(&alice, "secret", b"data");
    assert!(open_bytes(&mallory, &sealed).is_err());
}

#[test]
fn every_flipped_byte_region_fails() {
    let key = keypair();
    let data: Vec<u8> = (0..(CHUNK_SIZE + 100)).map(|i| (i % 256) as u8).collect();
    let sealed = seal_bytes(&key, "f", &data);
    // Flip one byte in each structural region: magic, KEM ct, salt, metadata
    // record, first chunk, final chunk.
    let offsets = [
        0usize,             // magic
        100,                // inside X-Wing ciphertext
        8 + 1120 + 5,       // inside salt
        8 + 1120 + 32 + 6,  // inside metadata record
        8 + 1120 + 32 + 80, // still metadata/first record area
        sealed.len() - 1,   // final byte of final record
    ];
    for &off in &offsets {
        let mut bad = sealed.clone();
        bad[off] ^= 0x01;
        assert!(
            open_bytes(&key, &bad).is_err(),
            "tampering at offset {off} was not detected"
        );
    }
}

#[test]
fn truncation_fails() {
    let key = keypair();
    let sealed = seal_bytes(&key, "f", &vec![7u8; CHUNK_SIZE + 500]);
    for cut in [sealed.len() - 1, sealed.len() - 17, 1200, 100] {
        assert!(
            open_bytes(&key, &sealed[..cut]).is_err(),
            "truncation to {cut} was not detected"
        );
    }
}

#[test]
fn record_reorder_fails() {
    let key = keypair();
    // Two full chunks + remainder -> records at predictable offsets.
    let data = vec![9u8; 2 * CHUNK_SIZE + 64];
    let sealed = seal_bytes(&key, "f", &data);

    // Parse record boundaries (u32-le length prefixes) after the fixed header.
    let header_len = 8 + 1120 + 32;
    let mut offsets = Vec::new();
    let mut pos = header_len;
    while pos < sealed.len() {
        let len = u32::from_le_bytes(sealed[pos..pos + 4].try_into().unwrap()) as usize;
        offsets.push((pos, 4 + len));
        pos += 4 + len;
    }
    assert!(offsets.len() >= 4, "expected metadata + >=3 chunks");

    // Swap the two full-size chunk records (indices 1 and 2).
    let (a_off, a_len) = offsets[1];
    let (b_off, b_len) = offsets[2];
    assert_eq!(a_len, b_len);
    let mut swapped = sealed.clone();
    swapped[a_off..a_off + a_len].copy_from_slice(&sealed[b_off..b_off + b_len]);
    swapped[b_off..b_off + b_len].copy_from_slice(&sealed[a_off..a_off + a_len]);
    assert!(
        open_bytes(&key, &swapped).is_err(),
        "record reordering was not detected"
    );
}

#[test]
fn cross_envelope_splice_fails() {
    let key = keypair();
    let data = vec![1u8; CHUNK_SIZE + 10];
    let sealed_a = seal_bytes(&key, "a", &data);
    let sealed_b = seal_bytes(&key, "b", &data);

    // Graft envelope B's first chunk record into envelope A.
    let header_len = 8 + 1120 + 32;
    let rec = |s: &[u8]| -> Vec<(usize, usize)> {
        let mut v = Vec::new();
        let mut pos = header_len;
        while pos < s.len() {
            let len = u32::from_le_bytes(s[pos..pos + 4].try_into().unwrap()) as usize;
            v.push((pos, 4 + len));
            pos += 4 + len;
        }
        v
    };
    let ra = rec(&sealed_a);
    let rb = rec(&sealed_b);
    let (a_off, a_len) = ra[1];
    let (b_off, b_len) = rb[1];
    assert_eq!(a_len, b_len);
    let mut spliced = sealed_a.clone();
    spliced[a_off..a_off + a_len].copy_from_slice(&sealed_b[b_off..b_off + b_len]);
    assert!(
        open_bytes(&key, &spliced).is_err(),
        "cross-envelope splice was not detected"
    );
}

#[test]
fn keyfile_round_trip_with_passphrase() {
    let key = keypair();
    let pass = Zeroizing::new(b"correct horse battery staple".to_vec());
    let secret = keyfile::encode_secret(&key, Some(&pass)).unwrap();

    let restored = keyfile::decode_secret(&secret, Some(&pass)).unwrap();
    assert_eq!(restored.public_key_bytes(), key.public_key_bytes());

    let wrong = Zeroizing::new(b"wrong passphrase".to_vec());
    assert!(matches!(
        keyfile::decode_secret(&secret, Some(&wrong)),
        Err(CryptoError::WrongPassphrase)
    ));
    assert!(keyfile::secret_needs_passphrase(&secret).unwrap());
}

#[test]
fn keyfile_round_trip_without_passphrase() {
    let key = keypair();
    let secret = keyfile::encode_secret(&key, None).unwrap();
    assert!(!keyfile::secret_needs_passphrase(&secret).unwrap());
    let restored = keyfile::decode_secret(&secret, None).unwrap();
    assert_eq!(restored.public_key_bytes(), key.public_key_bytes());
}

#[test]
fn public_key_text_round_trip() {
    let key = keypair();
    let text = keyfile::encode_public(key.public_key_bytes());
    let decoded = keyfile::decode_public(&text).unwrap();
    assert_eq!(&decoded, key.public_key_bytes());
    assert!(keyfile::decode_public("garbage").is_err());
}

#[test]
fn tampered_keyfile_kdf_params_fail() {
    let key = keypair();
    let pass = Zeroizing::new(b"pw".to_vec());
    let mut secret = keyfile::encode_secret(&key, Some(&pass)).unwrap();
    // Attempt a KDF downgrade: zero out the m_cost field (bytes 9..13).
    secret[9..13].copy_from_slice(&1024u32.to_le_bytes());
    assert!(keyfile::decode_secret(&secret, Some(&pass)).is_err());
}
