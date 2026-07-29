//! Direct TCP transport (no anonymity — LAN/clearnet or testing).

use std::net::{TcpListener as StdTcpListener, TcpStream};

use crate::crypto::{CryptoError, Result};

use super::{Listener, Transport};

pub struct TcpTransport;

impl Transport for TcpTransport {
    type Connection = TcpStream;

    fn dial(&self, addr: &str) -> Result<TcpStream> {
        let stream = TcpStream::connect(addr).map_err(CryptoError::Io)?;
        stream.set_nodelay(true).ok();
        Ok(stream)
    }
}

pub struct TcpListener {
    inner: StdTcpListener,
}

impl TcpListener {
    /// Bind to an address like `127.0.0.1:9878` or `0.0.0.0:0` (ephemeral).
    pub fn bind(addr: &str) -> Result<Self> {
        Ok(Self {
            inner: StdTcpListener::bind(addr).map_err(CryptoError::Io)?,
        })
    }
}

impl Listener for TcpListener {
    type Connection = TcpStream;

    fn accept(&self) -> Result<TcpStream> {
        let (stream, _peer) = self.inner.accept().map_err(CryptoError::Io)?;
        stream.set_nodelay(true).ok();
        Ok(stream)
    }

    fn address(&self) -> Result<String> {
        Ok(self.inner.local_addr().map_err(CryptoError::Io)?.to_string())
    }
}
