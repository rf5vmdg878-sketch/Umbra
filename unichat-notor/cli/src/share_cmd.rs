//! `unichat share` — ephemeral file sharing (Phase 6).
//!
//! Direct-TCP transport (no-Tor fork). `send` hosts a file for a bounded number
//! of downloads (auto-stops after); `download` fetches one. `receive` runs an
//! anonymous dropbox; `upload` pushes a file to one. All content is sealed
//! under the share key, so the carrier only ever sees ciphertext.

use std::net::TcpListener;
use std::path::Path;

use anyhow::{Context, Result};
use unichat_core::share::host::{download, upload, ShareHost};
use unichat_core::share::{open_content, ReceiveRef, ReceiveShare, Share, ShareRef};
use unichat_core::transport::tcp::TcpTransport;

/// Host a file until it has been downloaded `downloads` times, then stop.
pub fn send(file: &Path, downloads: usize, bind: &str) -> Result<()> {
    let data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let filename = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let share = Share::create(&filename, &data)?;
    let id = *share.id();

    let host = ShareHost::new();
    host.host_send(&share, downloads.max(1));
    let listener = TcpListener::bind(bind).with_context(|| format!("cannot bind {bind}"))?;
    println!("hosting '{filename}' ({} bytes) on {}", data.len(), listener.local_addr()?);
    println!("downloads allowed: {}", downloads.max(1));
    println!("\nGive the recipient this descriptor (over a secure channel):");
    println!("{}", share.descriptor());
    println!("\nwaiting for download(s)…");

    for conn in listener.incoming() {
        let conn = conn.context("accept failed")?;
        // Handle sequentially: a single small file, auto-stop on exhaustion.
        let _ = host.handle_connection(conn);
        let left = host.send_remaining(&id);
        if left == 0 {
            println!("download complete — share auto-stopped");
            break;
        }
        println!("downloaded; {left} remaining");
    }
    Ok(())
}

pub fn download_cmd(from: &str, descriptor: &str, out: &Path) -> Result<()> {
    let sref = ShareRef::from_descriptor(descriptor).context("invalid share descriptor")?;
    let (name, data) = download(&TcpTransport, from, &sref)
        .with_context(|| format!("download from {from} failed"))?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    std::fs::write(out, &data).with_context(|| format!("writing {}", out.display()))?;
    println!("downloaded '{name}' -> {} ({} bytes)", out.display(), data.len());
    Ok(())
}

/// Run an anonymous dropbox, writing decrypted uploads into `out_dir`.
pub fn receive(bind: &str, out_dir: &Path, label: &str) -> Result<()> {
    std::fs::create_dir_all(out_dir).ok();
    let dropbox = ReceiveShare::create(label);
    let id = *dropbox.id();
    let host = ShareHost::new();
    host.host_receive(dropbox.id(), dropbox.key());

    let listener = TcpListener::bind(bind).with_context(|| format!("cannot bind {bind}"))?;
    println!("receive dropbox '{label}' on {}", listener.local_addr()?);
    println!("uploads are size-capped and never executed.");
    println!("\nGive uploaders this descriptor (over a secure channel):");
    println!("{}", dropbox.descriptor());
    println!("\nwaiting for uploads…");

    let mut seen = 0usize;
    for conn in listener.incoming() {
        let conn = conn.context("accept failed")?;
        let _ = host.handle_connection(conn);
        let blobs = host.received(&id);
        while seen < blobs.len() {
            match open_content(dropbox.key(), &id, &blobs[seen]) {
                Ok((name, data)) => {
                    let safe = sanitize(&name);
                    let path = out_dir.join(&safe);
                    if let Err(e) = std::fs::write(&path, &data) {
                        eprintln!("failed to write {}: {e}", path.display());
                    } else {
                        println!("received '{safe}' ({} bytes) -> {}", data.len(), path.display());
                    }
                }
                Err(_) => eprintln!("(skipped an undecryptable upload)"),
            }
            seen += 1;
        }
    }
    Ok(())
}

pub fn upload_cmd(to: &str, descriptor: &str, file: &Path) -> Result<()> {
    let dropbox = ReceiveRef::from_descriptor(descriptor).context("invalid receive descriptor")?;
    let data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let filename = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    upload(&TcpTransport, to, &dropbox, &filename, &data)
        .with_context(|| format!("upload to {to} failed"))?;
    println!("uploaded '{filename}' ({} bytes) to dropbox '{}'", data.len(), dropbox.label);
    Ok(())
}

/// Reduce an upload-supplied filename to a safe basename.
fn sanitize(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        .take(200)
        .collect::<String>();
    let t = base.trim().trim_end_matches('.').to_string();
    if t.is_empty() || t == "." || t == ".." {
        "upload.bin".into()
    } else {
        t
    }
}
