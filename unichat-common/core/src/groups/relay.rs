//! Untrusted group relay (Cwtch's "dumb server").
//!
//! Stores opaque group blobs addressed by public group id and forwards them to
//! whoever asks. It cannot read blobs, does not know authorship, and enforces
//! no membership — it is deliberately trivial. Members fetch with a cursor
//! (server-assigned index) to receive only new messages, and discard anything
//! that fails to decrypt/authenticate. Spam is bounded by [`MAX_MSGS_PER_GROUP`]
//! and [`MAX_BLOB_SIZE`]; stronger anti-abuse (proof-of-work, tokens) is future
//! work.
//!
//! Wire protocol (`u32-le length ‖ JSON` frames):
//! ```text
//! post:  -> Post{group_id, blob}       <- Posted{count} | Err
//! fetch: -> Fetch{group_id, since}     <- Msgs{blobs, cursor} | Err
//! ```

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::{CryptoError, Result};
use crate::transport::Transport;

pub const MAX_BLOB_SIZE: usize = 128 * 1024;
pub const MAX_MSGS_PER_GROUP: usize = 4096;
const MAX_FRAME: usize = MAX_BLOB_SIZE + 4096;

#[derive(Serialize, Deserialize)]
enum Req {
    Post { group: String, blob: String },
    Fetch { group: String, since: usize },
}

#[derive(Serialize, Deserialize)]
enum Resp {
    Posted { count: usize },
    Msgs { blobs: Vec<String>, cursor: usize },
    Err { msg: String },
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
        .map_err(|_| CryptoError::Protocol("relay connection closed"))?;
    let n = u32::from_le_bytes(len) as usize;
    if n > max {
        return Err(CryptoError::Protocol("relay frame too large"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .map_err(|_| CryptoError::Protocol("relay frame truncated"))?;
    Ok(buf)
}

fn send(w: &mut impl Write, resp: &Resp) -> Result<()> {
    let bytes = serde_json::to_vec(resp).map_err(|_| CryptoError::Protocol("resp encode"))?;
    write_frame(w, &bytes)
}

fn valid_group(g: &str) -> bool {
    B64.decode(g).map(|v| v.len() == super::GROUP_ID_SIZE).unwrap_or(false)
}

/// In-memory relay store; clones share the backing map.
#[derive(Clone, Default)]
pub struct GroupRelay {
    inner: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>,
}

impl GroupRelay {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count(&self, group_id: &[u8; super::GROUP_ID_SIZE]) -> usize {
        self.inner
            .lock()
            .unwrap()
            .get(&B64.encode(group_id))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Opaque JSON snapshot of the whole spool (for encrypted-at-rest
    /// persistence by a relay server). The blobs are already sealed by clients;
    /// the server encrypts this snapshot again on disk.
    pub fn snapshot_bytes(&self) -> Vec<u8> {
        let map = self.inner.lock().unwrap();
        let view: std::collections::BTreeMap<String, Vec<String>> = map
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().map(|b| B64.encode(b)).collect()))
            .collect();
        serde_json::to_vec(&view).unwrap_or_default()
    }

    /// Restore a snapshot produced by [`Self::snapshot_bytes`]. Additive.
    pub fn restore_bytes(&self, data: &[u8]) {
        if let Ok(view) =
            serde_json::from_slice::<std::collections::BTreeMap<String, Vec<String>>>(data)
        {
            let mut map = self.inner.lock().unwrap();
            for (k, blobs) in view {
                let entry = map.entry(k).or_default();
                for b in blobs {
                    if let Ok(bytes) = B64.decode(&b) {
                        entry.push(bytes);
                    }
                }
            }
        }
    }

    /// Handle one client connection. A connection may issue multiple posts /
    /// fetches; it ends when the client disconnects.
    pub fn handle_connection<S: Read + Write>(&self, mut conn: S) -> Result<()> {
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
                Req::Post { group, blob } => {
                    let bytes = B64.decode(&blob).unwrap_or_default();
                    if !valid_group(&group) || bytes.is_empty() || bytes.len() > MAX_BLOB_SIZE {
                        send(&mut conn, &Resp::Err { msg: "invalid post".into() })?;
                        continue;
                    }
                    let count = {
                        let mut map = self.inner.lock().unwrap();
                        let q = map.entry(group).or_default();
                        if q.len() >= MAX_MSGS_PER_GROUP {
                            drop(map);
                            send(&mut conn, &Resp::Err { msg: "group full".into() })?;
                            continue;
                        }
                        q.push(bytes);
                        q.len()
                    };
                    send(&mut conn, &Resp::Posted { count })?;
                }
                Req::Fetch { group, since } => {
                    if !valid_group(&group) {
                        send(&mut conn, &Resp::Err { msg: "bad group".into() })?;
                        continue;
                    }
                    let (blobs, cursor) = {
                        let map = self.inner.lock().unwrap();
                        let all = map.get(&group).map(|v| v.as_slice()).unwrap_or(&[]);
                        let start = since.min(all.len());
                        let slice: Vec<String> = all[start..].iter().map(|b| B64.encode(b)).collect();
                        (slice, all.len())
                    };
                    send(&mut conn, &Resp::Msgs { blobs, cursor })?;
                }
            }
        }
    }
}

/// Post a blob to a group on the relay at `addr`.
pub fn post<T: Transport>(
    transport: &T,
    addr: &str,
    group_id: &[u8; super::GROUP_ID_SIZE],
    blob: &[u8],
) -> Result<usize> {
    let mut conn = transport.dial(addr)?;
    let req = Req::Post {
        group: B64.encode(group_id),
        blob: B64.encode(blob),
    };
    write_frame(
        &mut conn,
        &serde_json::to_vec(&req).map_err(|_| CryptoError::Protocol("req encode"))?,
    )?;
    match parse_resp(&mut conn)? {
        Resp::Posted { count } => Ok(count),
        Resp::Err { .. } => Err(CryptoError::Protocol("relay rejected post")),
        _ => Err(CryptoError::Protocol("unexpected relay response")),
    }
}

/// Fetch blobs posted after `since`; returns (blobs, new cursor).
pub fn fetch<T: Transport>(
    transport: &T,
    addr: &str,
    group_id: &[u8; super::GROUP_ID_SIZE],
    since: usize,
) -> Result<(Vec<Vec<u8>>, usize)> {
    let mut conn = transport.dial(addr)?;
    let req = Req::Fetch {
        group: B64.encode(group_id),
        since,
    };
    write_frame(
        &mut conn,
        &serde_json::to_vec(&req).map_err(|_| CryptoError::Protocol("req encode"))?,
    )?;
    match parse_resp(&mut conn)? {
        Resp::Msgs { blobs, cursor } => {
            let decoded = blobs
                .iter()
                .map(|b| B64.decode(b).map_err(|_| CryptoError::Protocol("bad blob")))
                .collect::<Result<Vec<_>>>()?;
            Ok((decoded, cursor))
        }
        Resp::Err { .. } => Err(CryptoError::Protocol("relay rejected fetch")),
        _ => Err(CryptoError::Protocol("unexpected relay response")),
    }
}

fn parse_resp(conn: &mut impl Read) -> Result<Resp> {
    let frame = read_frame(conn, MAX_FRAME)?;
    serde_json::from_slice(&frame).map_err(|_| CryptoError::Protocol("bad relay response"))
}
