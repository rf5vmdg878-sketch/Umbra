//! End-to-end encrypted streaming file transfer over an established session
//! ([`crate::session::SecureChannel`]). Because the channel is E2E, the file's
//! contents and name are protected in transit — including when the session is
//! carried through a relay, which only ever sees ciphertext.
//!
//! Flow: sender offers `{name, size}` → receiver accepts/declines → sender
//! streams base64 chunks until the final one. Each chunk rides inside the
//! channel's authenticated AEAD frames.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::crypto::{CryptoError, Result};
use crate::session::{AppMsg, SecureChannel};

const CHUNK: usize = 48 * 1024;

/// Offer and, if accepted, stream `data` as a file named `name`.
/// Returns `Ok(false)` if the peer declined.
pub fn send_file<S: std::io::Read + std::io::Write>(
    ch: &mut SecureChannel<S>,
    name: &str,
    data: &[u8],
) -> Result<bool> {
    ch.send(&AppMsg::FileOffer {
        name: name.to_string(),
        size: data.len() as u64,
    })?;
    match ch.recv()? {
        Some(AppMsg::FileAccept { accept: true }) => {}
        Some(AppMsg::FileAccept { accept: false }) => return Ok(false),
        _ => return Err(CryptoError::Protocol("expected file accept")),
    }

    if data.is_empty() {
        ch.send(&AppMsg::FileChunk {
            index: 0,
            last: true,
            data: String::new(),
        })?;
        return Ok(true);
    }
    let total = data.len().div_ceil(CHUNK);
    for (i, part) in data.chunks(CHUNK).enumerate() {
        ch.send(&AppMsg::FileChunk {
            index: i as u32,
            last: i + 1 == total,
            data: B64.encode(part),
        })?;
    }
    Ok(true)
}

/// Receive an offered file. `accept` decides whether to take it. Returns the
/// `(name, data)` on success, or `Ok(None)` if declined or no offer arrived.
pub fn recv_file<S: std::io::Read + std::io::Write>(
    ch: &mut SecureChannel<S>,
    accept: bool,
) -> Result<Option<(String, Vec<u8>)>> {
    let (name, size) = match ch.recv()? {
        Some(AppMsg::FileOffer { name, size }) => (name, size),
        None => return Ok(None),
        Some(_) => return Err(CryptoError::Protocol("expected a file offer")),
    };
    ch.send(&AppMsg::FileAccept { accept })?;
    if !accept {
        return Ok(None);
    }

    let mut data: Vec<u8> = Vec::new();
    loop {
        match ch.recv()? {
            Some(AppMsg::FileChunk { last, data: b64, .. }) => {
                if !b64.is_empty() {
                    let bytes = B64
                        .decode(&b64)
                        .map_err(|_| CryptoError::Malformed("bad file chunk"))?;
                    data.extend_from_slice(&bytes);
                }
                if data.len() as u64 > size.saturating_add(CHUNK as u64) {
                    return Err(CryptoError::Malformed("more data than offered"));
                }
                if last {
                    break;
                }
            }
            None => return Err(CryptoError::Protocol("connection closed mid-transfer")),
            Some(_) => return Err(CryptoError::Protocol("expected a file chunk")),
        }
    }
    if data.len() as u64 != size {
        return Err(CryptoError::Malformed("transferred size does not match offer"));
    }
    Ok(Some((name, data)))
}
