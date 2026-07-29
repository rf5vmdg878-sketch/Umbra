//! Deterministic directory archive: pack a whole directory tree into one byte
//! blob and back. Used to store a live directory — notably arti's Tor state dir
//! (onion-service keys, descriptors) — as a single encrypted vault object, so at
//! rest nothing on disk reveals that the machine runs an onion service.
//!
//! Format: `UDIR` || u32 count || repeat{ u16 path_len, path (utf8, '/'-joined
//! relative), u64 data_len, data }. Paths are sanitized on extract (no `..`, no
//! absolute/prefix components) to prevent traversal.

use std::path::{Component, Path, PathBuf};

use crate::crypto::{CryptoError, Result};

const MAGIC: &[u8; 4] = b"UDIR";
const MAX_ENTRIES: usize = 200_000;
const MAX_FILE: usize = 512 * 1024 * 1024;

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(CryptoError::Io(e)),
    };
    for entry in rd {
        let entry = entry.map_err(CryptoError::Io)?;
        let path = entry.path();
        let ft = entry.file_type().map_err(CryptoError::Io)?;
        if ft.is_dir() {
            collect(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| CryptoError::Malformed("archive path escaped root"))?;
            // Normalize to '/'-joined so archives are portable across platforms.
            let rel_str = rel
                .components()
                .filter_map(|c| match c {
                    Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/");
            if rel_str.is_empty() {
                continue;
            }
            let data = std::fs::read(&path).map_err(CryptoError::Io)?;
            out.push((rel_str, data));
        }
        // symlinks / other types are skipped
    }
    Ok(())
}

/// Pack every regular file under `dir` (recursively) into one blob.
pub fn archive_dir(dir: &Path) -> Result<Vec<u8>> {
    let mut entries = Vec::new();
    collect(dir, dir, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic ordering

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (rel, data) in &entries {
        out.extend_from_slice(&(rel.len() as u16).to_le_bytes());
        out.extend_from_slice(rel.as_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    }
    Ok(out)
}

/// Sanitize a '/'-joined relative path into a safe join under `base`.
fn safe_join(base: &Path, rel: &str) -> Option<PathBuf> {
    let mut p = base.to_path_buf();
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.contains('\\') {
            return None;
        }
        p.push(seg);
    }
    Some(p)
}

/// Recreate the archived files under `dir` (created if needed).
pub fn extract_dir(bytes: &[u8], dir: &Path) -> Result<()> {
    if bytes.len() < 8 || &bytes[..4] != MAGIC {
        return Err(CryptoError::Malformed("bad directory archive magic"));
    }
    let count = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if count > MAX_ENTRIES {
        return Err(CryptoError::Malformed("archive entry count implausible"));
    }
    std::fs::create_dir_all(dir).map_err(CryptoError::Io)?;

    let mut off = 8;
    for _ in 0..count {
        if off + 2 > bytes.len() {
            return Err(CryptoError::Malformed("archive truncated"));
        }
        let plen = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()) as usize;
        off += 2;
        if off + plen + 8 > bytes.len() {
            return Err(CryptoError::Malformed("archive truncated"));
        }
        let rel = std::str::from_utf8(&bytes[off..off + plen])
            .map_err(|_| CryptoError::Malformed("archive path not utf8"))?
            .to_owned();
        off += plen;
        let dlen = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()) as usize;
        off += 8;
        if dlen > MAX_FILE || off + dlen > bytes.len() {
            return Err(CryptoError::Malformed("archive file length invalid"));
        }
        let data = &bytes[off..off + dlen];
        off += dlen;

        let target = safe_join(dir, &rel)
            .ok_or(CryptoError::Malformed("unsafe path in archive"))?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(CryptoError::Io)?;
        }
        std::fs::write(&target, data).map_err(CryptoError::Io)?;
    }
    Ok(())
}

/// Best-effort wipe of a directory tree: overwrite each file with zeros, then
/// remove it. NOTE: on journaling filesystems / SSDs the overwrite is not a
/// guaranteed secure erase — it reduces, not eliminates, on-disk remnants.
pub fn wipe_dir(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => wipe_dir(&path),
                Ok(ft) if ft.is_file() => {
                    if let Ok(meta) = entry.metadata() {
                        let _ = std::fs::write(&path, vec![0u8; meta.len() as usize]);
                    }
                    let _ = std::fs::remove_file(&path);
                }
                _ => {}
            }
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}
