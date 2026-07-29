//! Lazily-bootstrapped shared Tor endpoint for the GUI engine (Tor build only).
//!
//! Bootstrapping arti is slow, so it happens once on the engine thread the first
//! time a Tor-routed operation runs, then the endpoint is reused.

use std::sync::{Arc, Mutex, OnceLock};

use unichat_core::transport::tor::TorEndpoint;

static EP: OnceLock<Mutex<Option<Arc<TorEndpoint>>>> = OnceLock::new();

/// Get (bootstrapping on first use) the shared Tor endpoint. State/cache live
/// under the OS temp dir so the GUI needs no extra configuration to try Tor.
pub fn endpoint() -> Result<Arc<TorEndpoint>, String> {
    let cell = EP.get_or_init(|| Mutex::new(None));
    let mut guard = cell.lock().map_err(|_| "endpoint lock poisoned".to_string())?;
    if let Some(ep) = guard.as_ref() {
        return Ok(ep.clone());
    }
    let base = std::env::temp_dir().join("umbra-tor");
    let state = base.join("state");
    let cache = base.join("cache");
    std::fs::create_dir_all(&state).ok();
    std::fs::create_dir_all(&cache).ok();
    let ep = Arc::new(TorEndpoint::bootstrap(&state, &cache).map_err(|e| e.to_string())?);
    *guard = Some(ep.clone());
    Ok(ep)
}
