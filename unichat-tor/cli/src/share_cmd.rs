//! `unichat share` — ephemeral file sharing (Phase 6).
//!
//! Tor build: runs over direct TCP, or over Tor with `--tor` (requires the
//! `tor` cargo feature). Content is sealed under the share key, so the carrier
//! only sees ciphertext.

use std::net::TcpListener;
use std::path::Path;

use anyhow::{Context, Result};
use unichat_core::share::host::{download, upload, ShareHost};
use unichat_core::share::{open_content, ReceiveRef, ReceiveShare, Share, ShareRef};
use unichat_core::transport::tcp::TcpTransport;

#[cfg(feature = "tor")]
const SHARE_ONION_PORT: u16 = 9920;

pub fn send(
    file: &Path,
    downloads: usize,
    bind: &str,
    use_tor: bool,
    _state_dir: Option<&Path>,
) -> Result<()> {
    let data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let filename = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let share = Share::create(&filename, &data)?;
    let id = *share.id();
    let host = ShareHost::new();
    host.host_send(&share, downloads.max(1));

    println!("hosting '{filename}' ({} bytes), downloads allowed: {}", data.len(), downloads.max(1));
    println!("\nGive the recipient this descriptor (over a secure channel):");
    println!("{}", share.descriptor());

    if use_tor {
        #[cfg(feature = "tor")]
        {
            use unichat_core::transport::Listener;
            let ep = bootstrap(_state_dir, "share")?;
            let listener = ep.listen("unichatshare", SHARE_ONION_PORT).context("onion launch failed")?;
            println!("share onion address: {}", listener.address()?);
            loop {
                let conn = listener.accept().context("accept failed")?;
                let _ = host.handle_connection(conn);
                if host.send_remaining(&id) == 0 {
                    println!("download complete — share auto-stopped");
                    return Ok(());
                }
            }
        }
        #[cfg(not(feature = "tor"))]
        anyhow::bail!("built without the `tor` feature");
    }

    let listener = TcpListener::bind(bind).with_context(|| format!("cannot bind {bind}"))?;
    println!("hosting on {}\nwaiting for download(s)…", listener.local_addr()?);
    for conn in listener.incoming() {
        let _ = host.handle_connection(conn.context("accept failed")?);
        let left = host.send_remaining(&id);
        if left == 0 {
            println!("download complete — share auto-stopped");
            break;
        }
        println!("downloaded; {left} remaining");
    }
    Ok(())
}

pub fn download_cmd(
    from: &str,
    descriptor: &str,
    out: &Path,
    use_tor: bool,
    _state_dir: Option<&Path>,
) -> Result<()> {
    let sref = ShareRef::from_descriptor(descriptor).context("invalid share descriptor")?;
    let (name, data) = if use_tor {
        #[cfg(feature = "tor")]
        {
            let ep = bootstrap(_state_dir, "share")?;
            download(&ep, from, &sref).context("download failed")?
        }
        #[cfg(not(feature = "tor"))]
        anyhow::bail!("built without the `tor` feature");
    } else {
        download(&TcpTransport, from, &sref).context("download failed")?
    };
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    std::fs::write(out, &data).with_context(|| format!("writing {}", out.display()))?;
    println!("downloaded '{name}' -> {} ({} bytes)", out.display(), data.len());
    Ok(())
}

pub fn receive(
    bind: &str,
    out_dir: &Path,
    label: &str,
    use_tor: bool,
    _state_dir: Option<&Path>,
) -> Result<()> {
    std::fs::create_dir_all(out_dir).ok();
    let dropbox = ReceiveShare::create(label);
    let id = *dropbox.id();
    let host = ShareHost::new();
    host.host_receive(dropbox.id(), dropbox.key());
    println!("receive dropbox '{label}' (uploads are size-capped and never executed)");
    println!("\nGive uploaders this descriptor (over a secure channel):");
    println!("{}", dropbox.descriptor());

    let key = *dropbox.key();
    let mut seen = 0usize;
    let mut drain = |host: &ShareHost| {
        let blobs = host.received(&id);
        while seen < blobs.len() {
            match open_content(&key, &id, &blobs[seen]) {
                Ok((name, data)) => {
                    let safe = sanitize(&name);
                    let path = out_dir.join(&safe);
                    match std::fs::write(&path, &data) {
                        Ok(()) => println!("received '{safe}' ({} bytes) -> {}", data.len(), path.display()),
                        Err(e) => eprintln!("failed to write {}: {e}", path.display()),
                    }
                }
                Err(_) => eprintln!("(skipped an undecryptable upload)"),
            }
            seen += 1;
        }
    };

    if use_tor {
        #[cfg(feature = "tor")]
        {
            use unichat_core::transport::Listener;
            let ep = bootstrap(_state_dir, "share")?;
            let listener = ep.listen("unichatdrop", SHARE_ONION_PORT).context("onion launch failed")?;
            println!("dropbox onion address: {}", listener.address()?);
            loop {
                let conn = listener.accept().context("accept failed")?;
                let _ = host.handle_connection(conn);
                drain(&host);
            }
        }
        #[cfg(not(feature = "tor"))]
        anyhow::bail!("built without the `tor` feature");
    }

    let listener = TcpListener::bind(bind).with_context(|| format!("cannot bind {bind}"))?;
    println!("listening on {}\nwaiting for uploads…", listener.local_addr()?);
    for conn in listener.incoming() {
        let _ = host.handle_connection(conn.context("accept failed")?);
        drain(&host);
    }
    Ok(())
}

pub fn upload_cmd(
    to: &str,
    descriptor: &str,
    file: &Path,
    use_tor: bool,
    _state_dir: Option<&Path>,
) -> Result<()> {
    let dropbox = ReceiveRef::from_descriptor(descriptor).context("invalid receive descriptor")?;
    let data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let filename = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    if use_tor {
        #[cfg(feature = "tor")]
        {
            let ep = bootstrap(_state_dir, "share")?;
            upload(&ep, to, &dropbox, &filename, &data).context("upload failed")?;
        }
        #[cfg(not(feature = "tor"))]
        anyhow::bail!("built without the `tor` feature");
    } else {
        upload(&TcpTransport, to, &dropbox, &filename, &data).context("upload failed")?;
    }
    println!("uploaded '{filename}' ({} bytes) to dropbox '{}'", data.len(), dropbox.label);
    Ok(())
}

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

#[cfg(feature = "tor")]
fn bootstrap(
    state_dir: Option<&Path>,
    tag: &str,
) -> Result<unichat_core::transport::tor::TorEndpoint> {
    use unichat_core::transport::tor::TorEndpoint;
    let state = state_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(&format!("{tag}.tor-state")).to_path_buf());
    std::fs::create_dir_all(&state).ok();
    let cache = format!("{tag}.tor-cache");
    std::fs::create_dir_all(&cache).ok();
    println!("[tor] bootstrapping…");
    TorEndpoint::bootstrap(&state, Path::new(&cache)).context("Tor bootstrap failed")
}
