//! Call relay: an untrusted rendezvous + byte-pump that pairs two callers by a
//! public `call_id` and forwards opaque bytes between them. It cannot read the
//! call — the peers run the E2E session handshake and encrypted media over it —
//! so it is exactly "route the call through *your own* server, no third party."
//!
//! Concrete to `TcpStream` (the relay server and tests use TCP; onion works by
//! fronting the TCP bind with a Tor HiddenService).

use std::collections::HashMap;
use std::io::Read;
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::crypto::{CryptoError, Result};

use super::{CALL_MAGIC, MAX_CALL_ID};

const PAIR_TIMEOUT: Duration = Duration::from_secs(60);

struct Rendezvous {
    peer: Mutex<Option<TcpStream>>,
    cv: Condvar,
}

/// Pairs and pumps call connections. Clone shares the backing map.
#[derive(Clone, Default)]
pub struct CallRelay {
    inner: Arc<Mutex<HashMap<String, Arc<Rendezvous>>>>,
}

impl CallRelay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of calls currently waiting for a second party.
    pub fn pending(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn handle_connection(&self, mut conn: TcpStream) -> Result<()> {
        let key = read_header(&mut conn)?;

        // Is someone already waiting on this call id?
        let existing = {
            let mut map = self.inner.lock().unwrap();
            map.remove(&key)
        };
        if let Some(rdv) = existing {
            // Second party: hand our stream to the waiting first party and go.
            *rdv.peer.lock().unwrap() = Some(conn);
            rdv.cv.notify_one();
            return Ok(());
        }

        // First party: register and wait for a peer.
        let rdv = Arc::new(Rendezvous {
            peer: Mutex::new(None),
            cv: Condvar::new(),
        });
        self.inner.lock().unwrap().insert(key.clone(), rdv.clone());

        let peer = {
            let guard = rdv.peer.lock().unwrap();
            let (mut guard, _timeout) = rdv
                .cv
                .wait_timeout_while(guard, PAIR_TIMEOUT, |p| p.is_none())
                .unwrap();
            guard.take()
        };
        match peer {
            Some(peer_conn) => pump(conn, peer_conn),
            None => {
                // Timed out; clean up if still registered.
                self.inner.lock().unwrap().remove(&key);
                Ok(())
            }
        }
    }
}

fn read_header(conn: &mut TcpStream) -> Result<String> {
    let mut magic = [0u8; 8];
    conn.read_exact(&mut magic)
        .map_err(|_| CryptoError::Handshake("call: connection closed before header"))?;
    if magic != CALL_MAGIC {
        return Err(CryptoError::Handshake("call: bad rendezvous magic"));
    }
    let mut l = [0u8; 1];
    conn.read_exact(&mut l).map_err(CryptoError::Io)?;
    let len = l[0] as usize;
    if len == 0 || len > MAX_CALL_ID {
        return Err(CryptoError::Protocol("call: bad call id length"));
    }
    let mut id = vec![0u8; len];
    conn.read_exact(&mut id).map_err(CryptoError::Io)?;
    let mut role = [0u8; 1];
    conn.read_exact(&mut role).map_err(CryptoError::Io)?;
    Ok(B64.encode(&id))
}

/// Copy bytes both directions between two paired sockets until either closes.
fn pump(a: TcpStream, b: TcpStream) -> Result<()> {
    let mut a_read = a.try_clone().map_err(CryptoError::Io)?;
    let mut b_write = b.try_clone().map_err(CryptoError::Io)?;
    let mut b_read = b;
    let mut a_write = a;

    // a -> b on a worker; b -> a here.
    let t = thread::spawn(move || {
        let _ = std::io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut b_read, &mut a_write);
    let _ = a_write.shutdown(Shutdown::Write);
    let _ = t.join();
    Ok(())
}
