//! Ephemeral share host + client (send/download and receive/upload).
//!
//! The host holds registered send-shares and receive-dropboxes in memory. A
//! client proves knowledge of the share key with a challenge-response
//! (`mac = SHA3-256(domain ‖ mode ‖ share_key ‖ nonce)`, compared in constant
//! time) before any content is transferred — OnionShare's client
//! authorization. Send-shares carry a **download budget** and auto-stop at
//! zero. Receive uploads are size-bounded and stored as opaque sealed blobs
//! (never executed).
//!
//! Wire protocol (`u32-le length ‖ JSON`, one download/upload per connection):
//! ```text
//! download: -> DownloadReq{id}        <- Challenge{nonce} | Err
//!           -> DownloadAuth{id,mac}    <- Content{blob} | Err
//! upload:   -> UploadReq{id}           <- Challenge{nonce} | Err
//!           -> UploadAuth{id,mac,blob}  <- Ok | Err
//! ```

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::crypto::{CryptoError, Result};
use crate::transport::Transport;

use super::{ReceiveRef, Share, ShareRef, SHARE_ID_SIZE, SHARE_KEY_SIZE};

pub const MAX_UPLOAD_SIZE: usize = 8 * 1024 * 1024;
const MAX_FRAME: usize = MAX_UPLOAD_SIZE + 8192;
const AUTH_DOMAIN: &[u8] = b"unichat-share-auth-v1\0";
const MODE_DOWNLOAD: u8 = 1;
const MODE_UPLOAD: u8 = 2;

fn mac(share_key: &[u8; SHARE_KEY_SIZE], mode: u8, nonce: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(AUTH_DOMAIN.len() + 1 + SHARE_KEY_SIZE + 32);
    buf.extend_from_slice(AUTH_DOMAIN);
    buf.push(mode);
    buf.extend_from_slice(share_key);
    buf.extend_from_slice(nonce);
    symcrypt::hash::sha3_256(&buf)
}

#[derive(Serialize, Deserialize)]
enum Req {
    DownloadReq { id: String },
    DownloadAuth { id: String, mac: String },
    UploadReq { id: String },
    UploadAuth { id: String, mac: String, blob: String },
}

#[derive(Serialize, Deserialize)]
enum Resp {
    Challenge { nonce: String },
    Content { blob: String },
    Ok,
    Err { msg: String },
}

struct SendEntry {
    key: [u8; SHARE_KEY_SIZE],
    blob: Vec<u8>,
    remaining: usize,
}

struct RecvEntry {
    key: [u8; SHARE_KEY_SIZE],
    uploads: Vec<Vec<u8>>,
}

#[derive(Default)]
struct HostState {
    sends: HashMap<String, SendEntry>,
    receives: HashMap<String, RecvEntry>,
}

/// In-memory host of shares and dropboxes; clones share the backing state.
#[derive(Clone, Default)]
pub struct ShareHost {
    inner: Arc<Mutex<HostState>>,
}

impl ShareHost {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a send-share allowing `downloads` retrievals (auto-stop after).
    pub fn host_send(&self, share: &Share, downloads: usize) {
        self.inner.lock().unwrap().sends.insert(
            B64.encode(share.id()),
            SendEntry {
                key: *share.key(),
                blob: share.sealed().to_vec(),
                remaining: downloads,
            },
        );
    }

    /// Register a receive dropbox.
    pub fn host_receive(&self, id: &[u8; SHARE_ID_SIZE], key: &[u8; SHARE_KEY_SIZE]) {
        self.inner.lock().unwrap().receives.insert(
            B64.encode(id),
            RecvEntry {
                key: *key,
                uploads: Vec::new(),
            },
        );
    }

    /// Remaining downloads for a send-share (0 if unknown/exhausted).
    pub fn send_remaining(&self, id: &[u8; SHARE_ID_SIZE]) -> usize {
        self.inner
            .lock()
            .unwrap()
            .sends
            .get(&B64.encode(id))
            .map(|e| e.remaining)
            .unwrap_or(0)
    }

    /// Sealed blobs uploaded to a receive dropbox (decrypt with `open_content`).
    pub fn received(&self, id: &[u8; SHARE_ID_SIZE]) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .receives
            .get(&B64.encode(id))
            .map(|e| e.uploads.clone())
            .unwrap_or_default()
    }

    pub fn handle_connection<S: Read + Write>(&self, mut conn: S) -> Result<()> {
        let mut pending: Option<(u8, String, [u8; 32])> = None; // (mode, id, nonce)
        loop {
            let frame = match read_frame(&mut conn, MAX_FRAME) {
                Ok(f) => f,
                Err(_) => return Ok(()),
            };
            let req: Req = match serde_json::from_slice(&frame) {
                Ok(r) => r,
                Err(_) => {
                    send(&mut conn, &Resp::Err { msg: "bad request".into() })?;
                    return Ok(());
                }
            };
            match req {
                Req::DownloadReq { id } => {
                    let ok = {
                        let st = self.inner.lock().unwrap();
                        st.sends.get(&id).map(|e| e.remaining > 0).unwrap_or(false)
                    };
                    if !ok {
                        send(&mut conn, &Resp::Err { msg: "no such share / exhausted".into() })?;
                        return Ok(());
                    }
                    let nonce = fresh_nonce();
                    pending = Some((MODE_DOWNLOAD, id, nonce));
                    send(&mut conn, &Resp::Challenge { nonce: B64.encode(nonce) })?;
                }
                Req::DownloadAuth { id, mac: client_mac } => {
                    let mut st = self.inner.lock().unwrap();
                    let entry = st.sends.get_mut(&id);
                    let good = matches!(&pending, Some((MODE_DOWNLOAD, pid, nonce))
                        if *pid == id
                            && entry.as_ref().map(|e| verify(&e.key, MODE_DOWNLOAD, nonce, &client_mac)).unwrap_or(false));
                    if !good {
                        drop(st);
                        send(&mut conn, &Resp::Err { msg: "auth failed".into() })?;
                        return Ok(());
                    }
                    let entry = entry.unwrap();
                    if entry.remaining == 0 {
                        drop(st);
                        send(&mut conn, &Resp::Err { msg: "exhausted".into() })?;
                        return Ok(());
                    }
                    entry.remaining -= 1;
                    let blob = entry.blob.clone();
                    if entry.remaining == 0 {
                        st.sends.remove(&id); // auto-stop: gone after the last download
                    }
                    drop(st);
                    send(&mut conn, &Resp::Content { blob: B64.encode(&blob) })?;
                    return Ok(());
                }
                Req::UploadReq { id } => {
                    let ok = self.inner.lock().unwrap().receives.contains_key(&id);
                    if !ok {
                        send(&mut conn, &Resp::Err { msg: "no such dropbox".into() })?;
                        return Ok(());
                    }
                    let nonce = fresh_nonce();
                    pending = Some((MODE_UPLOAD, id, nonce));
                    send(&mut conn, &Resp::Challenge { nonce: B64.encode(nonce) })?;
                }
                Req::UploadAuth { id, mac: client_mac, blob } => {
                    let bytes = B64.decode(&blob).unwrap_or_default();
                    let mut st = self.inner.lock().unwrap();
                    let entry = st.receives.get_mut(&id);
                    let good = matches!(&pending, Some((MODE_UPLOAD, pid, nonce))
                        if *pid == id
                            && entry.as_ref().map(|e| verify(&e.key, MODE_UPLOAD, nonce, &client_mac)).unwrap_or(false));
                    if !good {
                        drop(st);
                        send(&mut conn, &Resp::Err { msg: "auth failed".into() })?;
                        return Ok(());
                    }
                    if bytes.is_empty() || bytes.len() > MAX_UPLOAD_SIZE {
                        drop(st);
                        send(&mut conn, &Resp::Err { msg: "bad upload size".into() })?;
                        return Ok(());
                    }
                    entry.unwrap().uploads.push(bytes);
                    drop(st);
                    send(&mut conn, &Resp::Ok)?;
                    return Ok(());
                }
            }
        }
    }
}

fn verify(key: &[u8; SHARE_KEY_SIZE], mode: u8, nonce: &[u8; 32], client_mac_b64: &str) -> bool {
    let client = match B64.decode(client_mac_b64) {
        Ok(v) if v.len() == 32 => v,
        _ => return false,
    };
    let expected = mac(key, mode, nonce);
    expected.ct_eq(&client[..]).into()
}

fn fresh_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    crate::crypto::random_bytes(&mut n);
    n
}

// ---- client side ----

/// Download and decrypt a share. Returns (filename, data).
pub fn download<T: Transport>(
    transport: &T,
    addr: &str,
    share: &ShareRef,
) -> Result<(String, Vec<u8>)> {
    let mut conn = transport.dial(addr)?;
    let id_b64 = B64.encode(share.id);
    write_json(&mut conn, &Req::DownloadReq { id: id_b64.clone() })?;
    let nonce = match parse_resp(&mut conn)? {
        Resp::Challenge { nonce } => decode_nonce(&nonce)?,
        Resp::Err { .. } => return Err(CryptoError::Protocol("share unavailable")),
        _ => return Err(CryptoError::Protocol("unexpected response")),
    };
    let m = mac(&share.key, MODE_DOWNLOAD, &nonce);
    write_json(
        &mut conn,
        &Req::DownloadAuth {
            id: id_b64,
            mac: B64.encode(m),
        },
    )?;
    match parse_resp(&mut conn)? {
        Resp::Content { blob } => {
            let bytes = B64
                .decode(&blob)
                .map_err(|_| CryptoError::Protocol("bad content"))?;
            super::open_content(&share.key, &share.id, &bytes)
        }
        Resp::Err { .. } => Err(CryptoError::Protocol("download rejected")),
        _ => Err(CryptoError::Protocol("unexpected response")),
    }
}

/// Seal and upload a file to a receive dropbox.
pub fn upload<T: Transport>(
    transport: &T,
    addr: &str,
    dropbox: &ReceiveRef,
    filename: &str,
    data: &[u8],
) -> Result<()> {
    let sealed = super::seal_content(&dropbox.key, &dropbox.id, filename, data)?;
    let mut conn = transport.dial(addr)?;
    let id_b64 = B64.encode(dropbox.id);
    write_json(&mut conn, &Req::UploadReq { id: id_b64.clone() })?;
    let nonce = match parse_resp(&mut conn)? {
        Resp::Challenge { nonce } => decode_nonce(&nonce)?,
        Resp::Err { .. } => return Err(CryptoError::Protocol("dropbox unavailable")),
        _ => return Err(CryptoError::Protocol("unexpected response")),
    };
    let m = mac(&dropbox.key, MODE_UPLOAD, &nonce);
    write_json(
        &mut conn,
        &Req::UploadAuth {
            id: id_b64,
            mac: B64.encode(m),
            blob: B64.encode(&sealed),
        },
    )?;
    match parse_resp(&mut conn)? {
        Resp::Ok => Ok(()),
        Resp::Err { .. } => Err(CryptoError::Protocol("upload rejected")),
        _ => Err(CryptoError::Protocol("unexpected response")),
    }
}

fn decode_nonce(s: &str) -> Result<[u8; 32]> {
    B64.decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(CryptoError::Protocol("bad challenge"))
}

fn write_json(w: &mut impl Write, req: &Req) -> Result<()> {
    let bytes = serde_json::to_vec(req).map_err(|_| CryptoError::Protocol("req encode"))?;
    write_frame(w, &bytes)
}

fn send(w: &mut impl Write, resp: &Resp) -> Result<()> {
    let bytes = serde_json::to_vec(resp).map_err(|_| CryptoError::Protocol("resp encode"))?;
    write_frame(w, &bytes)
}

fn parse_resp(conn: &mut impl Read) -> Result<Resp> {
    let frame = read_frame(conn, MAX_FRAME)?;
    serde_json::from_slice(&frame).map_err(|_| CryptoError::Protocol("bad response"))
}

fn write_frame(w: &mut impl Write, payload: &[u8]) -> Result<()> {
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

fn read_frame(r: &mut impl Read, max: usize) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .map_err(|_| CryptoError::Protocol("share connection closed"))?;
    let n = u32::from_le_bytes(len) as usize;
    if n > max {
        return Err(CryptoError::Protocol("share frame too large"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .map_err(|_| CryptoError::Protocol("share frame truncated"))?;
    Ok(buf)
}
