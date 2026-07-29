//! Runtime integrity / anti-tamper.
//!
//! HONEST SCOPE: no pure-software check can make a binary *immutable* — an
//! attacker who can rewrite the files on disk can also patch out the check.
//! What this provides is strong **tamper-evidence**: the app verifies, at
//! startup and periodically at runtime, that its own executable and declared
//! assets match a manifest that is Ed25519-signed by the release key. Any
//! mismatch (a stripped/rewritten/back-doored binary, a swapped asset) makes it
//! refuse to run. True immutability comes from pairing this with OS controls —
//! Authenticode code-signing + owner-only, read-only ACLs — which are set up by
//! `harden.ps1` and documented in `docs/hardening.md`.
//!
//! Manifest file (`umbra.manifest`, next to the executable):
//! ```text
//! magic     8   "UMBRAMF1"
//! count     4   u32-le number of entries
//! entries       repeat: u16-le path_len, path (utf8, relative to exe dir), sha256[32]
//! sig      64   Ed25519 over everything above, verified with RELEASE_PUBKEY
//! ```
//! Paths are exe-dir-relative; the executable lists itself, so a rewritten exe
//! fails its own hash check.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Ed25519 public key that signs release manifests. All-zero = **unprovisioned**
/// (developer build): integrity is reported as unverified and NOT enforced.
/// Set this to the real release public key (see `umbra-manifest genkey`) to arm
/// tamper enforcement in shipped builds.
pub const RELEASE_PUBKEY: [u8; 32] = [
    0x27, 0xa9, 0xfd, 0xe1, 0xd3, 0x48, 0x47, 0x7c, 0x1f, 0x42, 0xb2, 0x01,
    0xa3, 0xf4, 0x56, 0xe9, 0x5f, 0x49, 0x08, 0x85, 0xd5, 0xc0, 0x70, 0x23,
    0x64, 0x25, 0xf5, 0xb2, 0x01, 0x47, 0x7f, 0x9f,
];

pub const MANIFEST_NAME: &str = "umbra.manifest";
const MAGIC: &[u8; 8] = b"UMBRAMF1";
const SIG_LEN: usize = 64;

/// SHA-256 (SymCrypt) of a byte slice.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    symcrypt::hash::sha256(data)
}

/// SHA-256 of a file's contents.
pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let data = std::fs::read(path)?;
    Ok(sha256(&data))
}

/// The signable body (everything before the signature) for `entries`.
pub fn manifest_body(entries: &[(String, [u8; 32])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (path, hash) in entries {
        let pb = path.as_bytes();
        out.extend_from_slice(&(pb.len() as u16).to_le_bytes());
        out.extend_from_slice(pb);
        out.extend_from_slice(hash);
    }
    out
}

/// Parse and verify a manifest's signature; returns the declared entries.
pub fn parse_verified(bytes: &[u8], pubkey: &[u8; 32]) -> Result<Vec<(String, [u8; 32])>, String> {
    if bytes.len() < 12 + SIG_LEN || &bytes[..8] != MAGIC {
        return Err("bad manifest magic/length".into());
    }
    let body = &bytes[..bytes.len() - SIG_LEN];
    let sig = &bytes[bytes.len() - SIG_LEN..];
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| "bad release public key".to_string())?;
    let sig = Signature::from_bytes(sig.try_into().map_err(|_| "bad signature".to_string())?);
    vk.verify(body, &sig)
        .map_err(|_| "manifest signature invalid".to_string())?;

    let count = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    let mut off = 12;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if off + 2 > body.len() {
            return Err("manifest truncated".into());
        }
        let plen = u16::from_le_bytes(body[off..off + 2].try_into().unwrap()) as usize;
        off += 2;
        if off + plen + 32 > body.len() {
            return Err("manifest truncated".into());
        }
        let path = String::from_utf8(body[off..off + plen].to_vec())
            .map_err(|_| "manifest path not utf8".to_string())?;
        off += plen;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&body[off..off + 32]);
        off += 32;
        entries.push((path, hash));
    }
    Ok(entries)
}

/// Outcome of an integrity check.
pub enum IntegrityStatus {
    /// Manifest present, signed, and every declared file matches.
    Verified,
    /// No release key provisioned or no manifest present (developer build).
    Unverified(String),
    /// A signed manifest exists but something no longer matches it.
    Tampered(String),
}

fn exe_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "executable has no parent dir".to_string())
}

/// Verify this process's executable and declared assets against the signed
/// manifest sitting next to the executable.
pub fn verify_startup(pubkey: &[u8; 32]) -> IntegrityStatus {
    if pubkey == &[0u8; 32] {
        return IntegrityStatus::Unverified("no release key provisioned".into());
    }
    let dir = match exe_dir() {
        Ok(d) => d,
        Err(e) => return IntegrityStatus::Unverified(e),
    };
    let manifest_path = dir.join(MANIFEST_NAME);
    let bytes = match std::fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return IntegrityStatus::Unverified("no manifest next to executable".into())
        }
        Err(e) => return IntegrityStatus::Tampered(format!("manifest unreadable: {e}")),
    };
    let entries = match parse_verified(&bytes, pubkey) {
        Ok(e) => e,
        Err(e) => return IntegrityStatus::Tampered(e),
    };
    for (rel, want) in &entries {
        let path = dir.join(rel);
        match sha256_file(&path) {
            Ok(got) if &got == want => {}
            Ok(_) => return IntegrityStatus::Tampered(format!("{rel} does not match manifest")),
            Err(e) => return IntegrityStatus::Tampered(format!("{rel} unreadable: {e}")),
        }
    }
    IntegrityStatus::Verified
}

/// True if a debugger is attached to this process.
#[cfg(windows)]
pub fn debugger_present() -> bool {
    // kernel32!IsDebuggerPresent — no crate needed.
    extern "system" {
        fn IsDebuggerPresent() -> i32;
    }
    unsafe { IsDebuggerPresent() != 0 }
}
#[cfg(target_os = "linux")]
pub fn debugger_present() -> bool {
    // A tracer (gdb/strace/ptrace) sets a non-zero TracerPid in /proc/self/status.
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("TracerPid:") {
                return v.trim().parse::<u32>().map(|p| p != 0).unwrap_or(false);
            }
        }
    }
    false
}
#[cfg(not(any(windows, target_os = "linux")))]
pub fn debugger_present() -> bool {
    false
}

/// Background self-defense: periodically re-verify integrity (catches an on-disk
/// swap while running) and, in release builds, bail if a debugger attaches.
pub fn spawn_guard(pubkey: [u8; 32]) {
    if pubkey == [0u8; 32] {
        return; // nothing to enforce in a developer build
    }
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(30));
        if let IntegrityStatus::Tampered(what) = verify_startup(&pubkey) {
            eprintln!("integrity: runtime tamper detected ({what}); exiting");
            std::process::exit(3);
        }
        #[cfg(all(any(windows, target_os = "linux"), not(debug_assertions)))]
        if debugger_present() {
            eprintln!("integrity: debugger attached at runtime; exiting");
            std::process::exit(3);
        }
    });
}

/// Startup gate for every Umbra binary. Verifies integrity, refuses to run on
/// tamper, warns (and continues) on a developer build, and arms the runtime
/// guard when a signed manifest is present.
pub fn enforce() {
    match verify_startup(&RELEASE_PUBKEY) {
        IntegrityStatus::Verified => {
            spawn_guard(RELEASE_PUBKEY);
        }
        IntegrityStatus::Unverified(reason) => {
            eprintln!("[integrity] unverified ({reason}); running without tamper protection");
        }
        IntegrityStatus::Tampered(what) => {
            eprintln!("[integrity] TAMPER DETECTED: {what}");
            eprintln!("[integrity] refusing to run a modified build.");
            std::process::exit(3);
        }
    }
    #[cfg(all(any(windows, target_os = "linux"), not(debug_assertions)))]
    if RELEASE_PUBKEY != [0u8; 32] && debugger_present() {
        eprintln!("[integrity] debugger detected; refusing to run.");
        std::process::exit(3);
    }
}
