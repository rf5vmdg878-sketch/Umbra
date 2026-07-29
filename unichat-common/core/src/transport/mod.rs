//! Transport abstraction (Phase 3).
//!
//! The session protocol (`crate::session`) runs over any bidirectional byte
//! stream, so the transport is a thin pluggable layer — the Briar
//! transport-plugin lesson, introduced here and reused by Phase 4's sync.
//!
//! This is the **Tor** build. Two transports implement the traits below:
//! - [`tcp::TcpTransport`] — direct TCP (LAN/clearnet or testing), always
//!   available;
//! - [`tor::TorEndpoint`] — Tor v3 onion-service transport, behind the `tor`
//!   cargo feature (pulls in arti).

pub mod tcp;

#[cfg(feature = "tor")]
pub mod tor;

use crate::crypto::Result;

/// A connected, bidirectional stream. `Send` so a connection can be handed to
/// a worker thread.
pub trait Conn: std::io::Read + std::io::Write + Send {}
impl<T: std::io::Read + std::io::Write + Send> Conn for T {}

/// Something that can dial out to a peer address and return a connection.
pub trait Transport {
    type Connection: Conn;
    fn dial(&self, addr: &str) -> Result<Self::Connection>;
}

/// Something that accepts incoming connections.
pub trait Listener {
    type Connection: Conn;
    fn accept(&self) -> Result<Self::Connection>;
    /// A human-usable address peers can dial (e.g. `127.0.0.1:9878`, or a
    /// `.onion` address in the Tor transport).
    fn address(&self) -> Result<String>;
}
