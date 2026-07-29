//! Tor onion-service transport (feature `tor`).
//!
//! This is the OnionShare/Ricochet transport model: each profile publishes a
//! v3 onion service as its address, and dials peers by their `.onion` address.
//! Tor (via arti) provides location anonymity and end-to-end encryption of the
//! carrier; the unichat session protocol layered on top provides post-quantum
//! confidentiality and mutual Ed25519 authentication — so a compromised or
//! malicious Tor circuit still cannot read or impersonate.
//!
//! arti is async (tokio); the session protocol is written against synchronous
//! `Read`/`Write`. [`BlockingStream`] bridges the two by driving each read and
//! write on a dedicated multi-threaded tokio runtime, so the rest of the
//! codebase stays transport-agnostic and single-threaded-friendly.
//!
//! Identity note: arti manages the onion-service secret key in its own
//! per-profile keystore (the `state_dir`). The onion address is therefore the
//! *transport locator*, while cryptographic identity is the profile's Ed25519
//! key authenticated inside the session handshake. Binding the two (deriving
//! the onion key from the profile identity) is a future refinement.

use std::io::{self, Read, Write};
use std::sync::Arc;

use arti_client::{TorClient, TorClientConfig};
use futures::StreamExt;
use safelog::DisplayRedacted;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, HsNickname, RunningOnionService};
use tor_rtcompat::PreferredRuntime;

use crate::crypto::{CryptoError, Result};

use super::{Listener, Transport};

fn err<E: std::fmt::Display>(ctx: &'static str) -> impl Fn(E) -> CryptoError {
    move |e| {
        CryptoError::Io(io::Error::other(format!("{ctx}: {e}")))
    }
}

/// A bootstrapped Tor client plus its runtime. Cloneable handle for dialing.
pub struct TorEndpoint {
    rt: Arc<Runtime>,
    client: Arc<TorClient<PreferredRuntime>>,
}

impl TorEndpoint {
    /// Bootstrap a Tor client. `state_dir` holds arti's persistent state
    /// (including onion-service keys); pass a per-profile directory.
    pub fn bootstrap(state_dir: &std::path::Path, cache_dir: &std::path::Path) -> Result<Self> {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(err("tokio runtime"))?,
        );
        let cfg = arti_client::config::TorClientConfigBuilder::from_directories(
            state_dir.to_path_buf(),
            cache_dir.to_path_buf(),
        );
        let config: TorClientConfig = cfg.build().map_err(err("arti config"))?;
        let client = rt
            .block_on(TorClient::create_bootstrapped(config))
            .map_err(err("bootstrap"))?;
        Ok(Self { rt, client })
    }
}

impl Transport for TorEndpoint {
    type Connection = BlockingStream;

    /// `addr` is `<56-char-base32>.onion:<port>`.
    fn dial(&self, addr: &str) -> Result<BlockingStream> {
        let stream = self
            .rt
            .block_on(self.client.connect(addr))
            .map_err(err("onion connect"))?;
        Ok(BlockingStream::new(self.rt.clone(), stream))
    }
}

/// A published onion service that accepts incoming streams.
pub struct TorListener {
    rt: Arc<Runtime>,
    onion: String,
    _service: Arc<RunningOnionService>,
    // Incoming, already-accepted data streams, pulled synchronously.
    incoming: AsyncMutex<futures::stream::BoxStream<'static, arti_client::DataStream>>,
}

impl TorEndpoint {
    /// Publish an onion service named `nickname` listening on virtual `port`.
    pub fn listen(&self, nickname: &str, port: u16) -> Result<TorListener> {
        let nick: HsNickname = nickname.parse().map_err(err("onion nickname"))?;
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname(nick)
            .build()
            .map_err(err("onion service config"))?;
        let (service, rend_requests) = self
            .client
            .launch_onion_service(svc_cfg)
            .map_err(err("launch onion service"))?
            .ok_or_else(|| CryptoError::Io(io::Error::other("onion service already running")))?;

        let onion = service
            .onion_address()
            .map(|a| format!("{}:{}", a.display_unredacted(), port))
            .ok_or_else(|| CryptoError::Io(io::Error::other("onion address not yet available")))?;

        // Translate rendezvous requests into accepted data streams. The onion
        // service advertises a single virtual port, so every incoming stream
        // is for us; accept them all.
        let stream_requests = handle_rend_requests(rend_requests);
        let incoming = stream_requests
            .filter_map(|req| async move {
                req.accept(tor_cell::relaycell::msg::Connected::new_empty())
                    .await
                    .ok()
            })
            .boxed();

        Ok(TorListener {
            rt: self.rt.clone(),
            onion,
            _service: service,
            incoming: AsyncMutex::new(incoming),
        })
    }
}

impl Listener for TorListener {
    type Connection = BlockingStream;

    fn accept(&self) -> Result<BlockingStream> {
        let stream = self.rt.block_on(async {
            let mut guard = self.incoming.lock().await;
            guard.next().await
        });
        match stream {
            Some(s) => Ok(BlockingStream::new(self.rt.clone(), s)),
            None => Err(CryptoError::Io(io::Error::other(
                "onion service stream ended",
            ))),
        }
    }

    fn address(&self) -> Result<String> {
        Ok(self.onion.clone())
    }
}

/// Adapts arti's async `DataStream` to synchronous `Read`/`Write` by driving
/// each operation on the shared tokio runtime.
pub struct BlockingStream {
    rt: Arc<Runtime>,
    inner: arti_client::DataStream,
}

impl BlockingStream {
    fn new(rt: Arc<Runtime>, inner: arti_client::DataStream) -> Self {
        Self { rt, inner }
    }
}

impl Read for BlockingStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rt = self.rt.clone();
        rt.block_on(self.inner.read(buf))
    }
}

impl Write for BlockingStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let rt = self.rt.clone();
        rt.block_on(self.inner.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        let rt = self.rt.clone();
        rt.block_on(self.inner.flush())
    }
}
