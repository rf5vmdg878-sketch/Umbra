//! Untrusted store-and-forward mailbox (Briar mailbox model).
//!
//! A mailbox is addressed by its **owner's Ed25519 identity public key**. Any
//! sender may `deposit` an opaque sealed blob for an owner (no auth — senders
//! are anonymous; spam is bounded by [`MAX_BLOBS_PER_OWNER`] and
//! [`MAX_BLOB_SIZE`]). Only the owner can `collect`, proven by signing a
//! server-issued random challenge with the owner's identity key. The mailbox
//! never sees plaintext (blobs are sealed to the owner's X-Wing key by the
//! sender) and never learns sender identities.
//!
//! Wire protocol (one connection, `u32-le length ‖ JSON` frames):
//! ```text
//! deposit:  -> Deposit{owner, blob}          <- Ok | Err
//! collect:  -> ChallengeReq{owner}           <- Challenge{nonce}
//!           -> Collect{owner, sig(nonce)}    <- Blobs{..} | Err   (then cleared)
//! ```

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::{CryptoError, Result};
use crate::identity::{verify_detached, Identity};
use crate::transport::Transport;

pub const MAX_BLOB_SIZE: usize = 256 * 1024;
pub const MAX_BLOBS_PER_OWNER: usize = 1024;
const MAX_FRAME: usize = MAX_BLOB_SIZE + 4096;
const CHALLENGE_DOMAIN: &[u8] = b"unichat-mailbox-collect-v1\0";

#[derive(Serialize, Deserialize)]
enum Req {
    Deposit { owner: String, blob: String },
    ChallengeReq { owner: String },
    Collect { owner: String, sig: String },
}

#[derive(Serialize, Deserialize)]
enum Resp {
    Ok,
    Challenge { nonce: String },
    Blobs { blobs: Vec<String> },
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
        .map_err(|_| CryptoError::Protocol("mailbox connection closed"))?;
    let n = u32::from_le_bytes(len) as usize;
    if n > max {
        return Err(CryptoError::Protocol("mailbox frame too large"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .map_err(|_| CryptoError::Protocol("mailbox frame truncated"))?;
    Ok(buf)
}

fn send(w: &mut impl Write, resp: &Resp) -> Result<()> {
    let bytes = serde_json::to_vec(resp).map_err(|_| CryptoError::Protocol("resp encode"))?;
    write_frame(w, &bytes)
}

fn owner_pk(owner: &str) -> Option<[u8; 32]> {
    B64.decode(owner).ok().and_then(|v| v.try_into().ok())
}

/// In-memory mailbox store. Clone shares the same backing map (cheap `Arc`),
/// so it can be handed to many connection-handler threads.
#[derive(Clone, Default)]
pub struct MailboxStore {
    inner: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>,
}

impl MailboxStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored blobs for an owner (test/introspection helper).
    pub fn len_for(&self, owner_id: &[u8; 32]) -> usize {
        self.inner
            .lock()
            .unwrap()
            .get(&B64.encode(owner_id))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Opaque JSON snapshot of the whole spool (for encrypted-at-rest
    /// persistence by a relay server).
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

    /// Handle one client connection to completion. Deposit is a single
    /// request; collect is a two-step challenge/response. The per-connection
    /// challenge nonce never leaves this function, so a signature captured on
    /// one connection cannot be replayed on another.
    pub fn handle_connection<S: Read + Write>(&self, mut conn: S) -> Result<()> {
        let mut pending_nonce: Option<(String, [u8; 32])> = None; // (owner, nonce)
        loop {
            let frame = match read_frame(&mut conn, MAX_FRAME) {
                Ok(f) => f,
                Err(_) => return Ok(()), // client hung up
            };
            let req: Req = match serde_json::from_slice(&frame) {
                Ok(r) => r,
                Err(_) => {
                    send(&mut conn, &Resp::Err { msg: "bad request".into() })?;
                    return Ok(());
                }
            };
            match req {
                Req::Deposit { owner, blob } => {
                    let ok = owner_pk(&owner).is_some();
                    let bytes = B64.decode(&blob).unwrap_or_default();
                    if !ok || bytes.is_empty() || bytes.len() > MAX_BLOB_SIZE {
                        send(&mut conn, &Resp::Err { msg: "invalid deposit".into() })?;
                        return Ok(());
                    }
                    {
                        let mut map = self.inner.lock().unwrap();
                        let q = map.entry(owner).or_default();
                        if q.len() >= MAX_BLOBS_PER_OWNER {
                            send(&mut conn, &Resp::Err { msg: "mailbox full".into() })?;
                            return Ok(());
                        }
                        q.push(bytes);
                    }
                    send(&mut conn, &Resp::Ok)?;
                }
                Req::ChallengeReq { owner } => {
                    if owner_pk(&owner).is_none() {
                        send(&mut conn, &Resp::Err { msg: "bad owner".into() })?;
                        return Ok(());
                    }
                    let mut nonce = [0u8; 32];
                    crate::crypto::random_bytes(&mut nonce);
                    pending_nonce = Some((owner, nonce));
                    send(
                        &mut conn,
                        &Resp::Challenge {
                            nonce: B64.encode(nonce),
                        },
                    )?;
                }
                Req::Collect { owner, sig } => {
                    let valid = match (&pending_nonce, owner_pk(&owner)) {
                        (Some((chal_owner, nonce)), Some(pk)) if *chal_owner == owner => {
                            let sig_bytes: Option<[u8; 64]> =
                                B64.decode(&sig).ok().and_then(|v| v.try_into().ok());
                            let mut msg = Vec::from(CHALLENGE_DOMAIN);
                            msg.extend_from_slice(nonce);
                            sig_bytes
                                .map(|s| verify_detached(&pk, &msg, &s))
                                .unwrap_or(false)
                        }
                        _ => false,
                    };
                    if !valid {
                        send(&mut conn, &Resp::Err { msg: "auth failed".into() })?;
                        return Ok(());
                    }
                    let blobs = {
                        let mut map = self.inner.lock().unwrap();
                        map.remove(&owner).unwrap_or_default()
                    };
                    let encoded = blobs.iter().map(|b| B64.encode(b)).collect();
                    send(&mut conn, &Resp::Blobs { blobs: encoded })?;
                    return Ok(());
                }
            }
        }
    }
}

/// Deposit a sealed blob for `recipient_id` at the mailbox reachable at `addr`
/// over `transport`.
pub fn deposit<T: Transport>(
    transport: &T,
    addr: &str,
    recipient_id: &[u8; 32],
    blob: &[u8],
) -> Result<()> {
    let mut conn = transport.dial(addr)?;
    let req = Req::Deposit {
        owner: B64.encode(recipient_id),
        blob: B64.encode(blob),
    };
    write_frame(
        &mut conn,
        &serde_json::to_vec(&req).map_err(|_| CryptoError::Protocol("req encode"))?,
    )?;
    match parse_resp(&mut conn)? {
        Resp::Ok => Ok(()),
        Resp::Err { msg } => Err(CryptoError::Protocol(leak(msg))),
        _ => Err(CryptoError::Protocol("unexpected mailbox response")),
    }
}

/// Collect all blobs for our own identity from the mailbox (authenticated).
pub fn collect<T: Transport>(
    transport: &T,
    addr: &str,
    identity: &Identity,
) -> Result<Vec<Vec<u8>>> {
    let owner = B64.encode(identity.public_bytes());
    let mut conn = transport.dial(addr)?;

    let req = Req::ChallengeReq {
        owner: owner.clone(),
    };
    write_frame(
        &mut conn,
        &serde_json::to_vec(&req).map_err(|_| CryptoError::Protocol("req encode"))?,
    )?;
    let nonce = match parse_resp(&mut conn)? {
        Resp::Challenge { nonce } => B64
            .decode(&nonce)
            .map_err(|_| CryptoError::Protocol("bad challenge"))?,
        Resp::Err { msg } => return Err(CryptoError::Protocol(leak(msg))),
        _ => return Err(CryptoError::Protocol("unexpected mailbox response")),
    };

    let mut signed = Vec::from(CHALLENGE_DOMAIN);
    signed.extend_from_slice(&nonce);
    let sig = identity.sign_detached(&signed);
    let req = Req::Collect {
        owner,
        sig: B64.encode(sig),
    };
    write_frame(
        &mut conn,
        &serde_json::to_vec(&req).map_err(|_| CryptoError::Protocol("req encode"))?,
    )?;
    match parse_resp(&mut conn)? {
        Resp::Blobs { blobs } => blobs
            .iter()
            .map(|b| B64.decode(b).map_err(|_| CryptoError::Protocol("bad blob")))
            .collect(),
        Resp::Err { msg } => Err(CryptoError::Protocol(leak(msg))),
        _ => Err(CryptoError::Protocol("unexpected mailbox response")),
    }
}

fn parse_resp(conn: &mut impl Read) -> Result<Resp> {
    let frame = read_frame(conn, MAX_FRAME)?;
    serde_json::from_slice(&frame).map_err(|_| CryptoError::Protocol("bad mailbox response"))
}

// The mailbox's own error strings are static; leak turns a received String into
// a &'static str only for surfacing (bounded set), avoiding an API change.
fn leak(_msg: String) -> &'static str {
    "mailbox rejected the request"
}
