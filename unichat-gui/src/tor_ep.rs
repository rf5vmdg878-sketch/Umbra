//! Lazily-bootstrapped shared Tor endpoint for the GUI engine (Tor build only).
//!
//! Bootstrapping arti is slow, so it happens once on the engine thread the first
//! time a Tor-routed operation runs, then the endpoint is reused.
//!
//! **State at rest:** arti keeps its state (onion-service keys, descriptors) in a
//! real directory while running. We keep that directory encrypted inside the
//! profile vault when the profile is locked: [`restore_state`] unpacks it before
//! the first Tor use, and [`persist_state`] (called on lock / session drop)
//! re-encrypts it into the vault and wipes the plaintext. HONEST LIMIT: while the
//! app is unlocked and running, the state dir is plaintext on disk (arti needs
//! it); a hard crash before lock can leave it — it is re-absorbed and
//! re-encrypted on the next lock.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use unichat_core::storage::archive;
use unichat_core::storage::UnlockedStore;
use unichat_core::transport::tor::TorEndpoint;

static EP: OnceLock<Mutex<Option<Arc<TorEndpoint>>>> = OnceLock::new();

/// Vault label under which the encrypted Tor state archive is stored.
const TOR_STATE_LABEL: &str = "tor-state";

fn base_dir() -> PathBuf {
    std::env::temp_dir().join("umbra-tor")
}
pub fn state_dir() -> PathBuf {
    base_dir().join("state")
}
fn cache_dir() -> PathBuf {
    base_dir().join("cache")
}

/// Get (bootstrapping on first use) the shared Tor endpoint.
pub fn endpoint() -> Result<Arc<TorEndpoint>, String> {
    let cell = EP.get_or_init(|| Mutex::new(None));
    let mut guard = cell.lock().map_err(|_| "endpoint lock poisoned".to_string())?;
    if let Some(ep) = guard.as_ref() {
        return Ok(ep.clone());
    }
    let state = state_dir();
    let cache = cache_dir();
    std::fs::create_dir_all(&state).ok();
    std::fs::create_dir_all(&cache).ok();
    let ep = Arc::new(TorEndpoint::bootstrap(&state, &cache).map_err(|e| e.to_string())?);
    *guard = Some(ep.clone());
    Ok(ep)
}

/// Decrypt the stored Tor state from the vault into the working state dir, if
/// present. Call once right after unlocking, before any Tor-routed operation.
pub fn restore_state(store: &UnlockedStore) {
    // Always start from a clean state dir: a crash before the previous lock can
    // leave another profile's onion keys behind, and extract_dir only merges on
    // top. Wiping first prevents cross-profile Tor-identity contamination.
    archive::wipe_dir(&state_dir());
    if let Ok(Some(blob)) = store.get_object(TOR_STATE_LABEL) {
        std::fs::create_dir_all(state_dir()).ok();
        let _ = archive::extract_dir(&blob, &state_dir());
    }
}

/// Drop the running endpoint so nothing holds the state dir open. Next Tor use
/// re-bootstraps.
pub fn shutdown() {
    if let Some(cell) = EP.get() {
        if let Ok(mut guard) = cell.lock() {
            *guard = None;
        }
    }
}

/// Re-encrypt the working Tor state into the vault (opaque object) and wipe the
/// plaintext. Call on lock / session drop.
pub fn persist_state(store: &UnlockedStore) {
    let sd = state_dir();
    if !sd.exists() {
        return;
    }
    if let Ok(blob) = archive::archive_dir(&sd) {
        if !blob.is_empty() {
            let _ = store.put_object(TOR_STATE_LABEL, &blob);
        }
    }
    archive::wipe_dir(&sd);
    // The cache is regenerable and non-sensitive, but clear it too for tidiness.
    archive::wipe_dir(&cache_dir());
}
