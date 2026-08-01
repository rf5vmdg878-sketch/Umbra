//! System sanitize / factory reset.
//!
//! Securely purges all **app-managed** state — the profile vault (profiles,
//! contacts, groups, cached history, Tor onion keys), the Tor working dirs, and
//! (on the relay) the encrypted spool + generated configs — so the app returns
//! to its installed defaults. Intended for an administrator cleaning a machine
//! for maintenance or before decommissioning.
//!
//! It never touches the installed program, the release signing key, or files the
//! user deliberately saved elsewhere (e.g. downloads pulled out of a chat) — only
//! the state the app itself creates.
//!
//! Wipes are best-effort secure: each file is overwritten with zeros before
//! removal. On journaling filesystems / SSDs overwrite is not a guaranteed
//! secure erase (it reduces, not eliminates, remnants) — for a hard guarantee,
//! pair this with full-disk encryption or media sanitization.

use std::path::{Path, PathBuf};

use crate::storage::archive::wipe_dir;

/// Outcome of a purge.
#[derive(Default)]
pub struct SanitizeReport {
    /// (path, approximate bytes reclaimed) for each target actually removed.
    pub removed: Vec<(PathBuf, u64)>,
    /// Targets that did not exist (nothing to do).
    pub missing: Vec<PathBuf>,
    /// Targets that could not be fully removed, with the reason.
    pub errors: Vec<(PathBuf, String)>,
}

impl SanitizeReport {
    pub fn removed_count(&self) -> usize {
        self.removed.len()
    }
    pub fn total_bytes(&self) -> u64 {
        self.removed.iter().map(|(_, b)| *b).sum()
    }
}

fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(path) {
        for e in rd.flatten() {
            match e.file_type() {
                Ok(ft) if ft.is_dir() => total += dir_size(&e.path()),
                Ok(ft) if ft.is_file() => total += e.metadata().map(|m| m.len()).unwrap_or(0),
                _ => {}
            }
        }
    }
    total
}

/// Best-effort secure wipe of a regular file: overwrite with zeros (chunked +
/// fsync'd), then remove. NEVER writes through a symlink — a symlinked target is
/// unlinked without touching whatever it points at.
fn wipe_file(path: &Path) -> std::io::Result<u64> {
    use std::io::Write;
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        std::fs::remove_file(path)?;
        return Ok(0);
    }
    let len = meta.len();
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
        let zeros = [0u8; 64 * 1024];
        let mut left = len;
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            if f.write_all(&zeros[..n]).is_err() {
                break;
            }
            left -= n as u64;
        }
        let _ = f.sync_all();
    }
    std::fs::remove_file(path)?;
    Ok(len)
}

/// Refuse obviously dangerous wipe targets — anything with no *named* component
/// (empty, ".", "..", "/", a drive root like "C:\", a UNC share root) — so a
/// bad/empty path can never recursively erase an unrelated tree.
fn refuse_reason(path: &Path) -> Option<&'static str> {
    use std::path::Component;
    if path.as_os_str().is_empty() {
        return Some("empty path");
    }
    if !path.components().any(|c| matches!(c, Component::Normal(_))) {
        return Some("root or current/parent directory (no named component)");
    }
    None
}

/// Wipe one target (file or directory) if it exists, recording the outcome.
pub fn wipe_path(path: &Path, report: &mut SanitizeReport) {
    if let Some(reason) = refuse_reason(path) {
        report
            .errors
            .push((path.to_path_buf(), format!("refused unsafe target ({reason})")));
        return;
    }
    match std::fs::symlink_metadata(path) {
        Err(_) => report.missing.push(path.to_path_buf()),
        Ok(m) if m.is_dir() => {
            let sz = dir_size(path);
            wipe_dir(path); // recursive overwrite + remove (from storage::archive)
            if path.exists() {
                report.errors.push((path.to_path_buf(), "not fully removed".into()));
            } else {
                report.removed.push((path.to_path_buf(), sz));
            }
        }
        Ok(_) => match wipe_file(path) {
            Ok(n) => report.removed.push((path.to_path_buf(), n)),
            Err(e) => report.errors.push((path.to_path_buf(), e.to_string())),
        },
    }
}

/// Securely purge every target. Non-existent targets are simply skipped.
pub fn purge(targets: &[PathBuf]) -> SanitizeReport {
    let mut report = SanitizeReport::default();
    for t in targets {
        wipe_path(t, &mut report);
    }
    report
}

/// The subset of `targets` that currently exist, with sizes — for a dry-run
/// preview before purging.
pub fn existing(targets: &[PathBuf]) -> Vec<(PathBuf, u64)> {
    targets
        .iter()
        .filter_map(|t| match std::fs::symlink_metadata(t) {
            Ok(m) if m.is_dir() => Some((t.clone(), dir_size(t))),
            Ok(m) => Some((t.clone(), m.len())),
            Err(_) => None,
        })
        .collect()
}

// ---- composable target categories (select what to clean) ----

/// The profile vault directory + a legacy single-file backup left by migration.
pub fn profile_targets(store: &Path) -> Vec<PathBuf> {
    vec![store.to_path_buf(), store.with_extension("legacy.bak")]
}

/// The GUI's Tor working directories (state + cache under the OS temp dir).
pub fn tor_targets() -> Vec<PathBuf> {
    vec![std::env::temp_dir().join("umbra-tor")]
}

/// Everything the desktop app manages for a given store (profiles + Tor).
pub fn app_targets(store: &Path) -> Vec<PathBuf> {
    let mut v = profile_targets(store);
    v.extend(tor_targets());
    v
}

/// Any `*.tor-state` / `*.tor-cache` working DIRECTORIES the CLI leaves in `cwd`.
/// Only real directories match (arti state/cache are dirs) — stray files or
/// symlinks that merely share the suffix are ignored, so an unrelated
/// `backup.tor-state` file (or a symlink) is never swept.
pub fn cli_tor_dirs_in(cwd: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(cwd) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_real_dir = e.file_type().map(|t| t.is_dir() && !t.is_symlink()).unwrap_or(false);
            if is_real_dir && (name.ends_with(".tor-state") || name.ends_with(".tor-cache")) {
                v.push(e.path());
            }
        }
    }
    v
}
