//! `unichat mailbox` / `unichat msg` — offline store-and-forward (Phase 4).
//!
//! Tor build: runs over direct TCP, or over Tor with `--tor` (requires the
//! `tor` cargo feature). A Tor mailbox is published as an onion service; senders
//! and collectors reach it anonymously.

use std::net::TcpListener;
use std::path::Path;
use std::thread;

use anyhow::{Context, Result};
use unichat_core::identity::Profile;
use unichat_core::sync::mailbox::{collect, deposit, MailboxStore};
use unichat_core::sync::{open_message, seal_message};
use unichat_core::transport::tcp::TcpTransport;

use crate::open_store;

#[cfg(feature = "tor")]
const MAILBOX_ONION_PORT: u16 = 9900;

pub fn mailbox_serve(bind: &str, use_tor: bool, _state_dir: Option<&Path>) -> Result<()> {
    let store = MailboxStore::new();
    if use_tor {
        #[cfg(feature = "tor")]
        {
            use unichat_core::transport::tor::TorEndpoint;
            use unichat_core::transport::Listener;
            let state = _state_dir
                .map(Path::to_path_buf)
                .unwrap_or_else(|| Path::new("mailbox.tor-state").to_path_buf());
            std::fs::create_dir_all(&state).ok();
            std::fs::create_dir_all("mailbox.tor-cache").ok();
            println!("[tor] bootstrapping…");
            let ep = TorEndpoint::bootstrap(&state, Path::new("mailbox.tor-cache"))
                .context("Tor bootstrap failed")?;
            let listener = ep
                .listen("unichatmailbox", MAILBOX_ONION_PORT)
                .context("onion launch failed")?;
            println!("mailbox onion address: {}", listener.address()?);
            loop {
                match listener.accept() {
                    Ok(c) => {
                        let s = store.clone();
                        thread::spawn(move || {
                            let _ = s.handle_connection(c);
                        });
                    }
                    Err(e) => eprintln!("accept error: {e}"),
                }
            }
        }
        #[cfg(not(feature = "tor"))]
        anyhow::bail!("built without the `tor` feature (rebuild with --features tor)");
    }

    let listener = TcpListener::bind(bind).with_context(|| format!("cannot bind {bind}"))?;
    println!("mailbox listening on {}", listener.local_addr()?);
    for conn in listener.incoming() {
        match conn {
            Ok(c) => {
                let s = store.clone();
                thread::spawn(move || {
                    let _ = s.handle_connection(c);
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

pub fn msg_send(
    store: &Path,
    to_alias: &str,
    via: &str,
    message: &str,
    use_tor: bool,
    _state_dir: Option<&Path>,
) -> Result<()> {
    let (_unlocked, profile) = open_store(store)?;
    let contact = profile
        .contact(to_alias)
        .with_context(|| format!("no contact aliased '{to_alias}'"))?;
    let recipient_id = contact.identity_pk()?;
    let recipient_xwing = contact.xwing_public()?;
    let blob = seal_message(
        &profile.identity()?,
        &recipient_id,
        &recipient_xwing,
        message.as_bytes(),
    )?;

    if use_tor {
        #[cfg(feature = "tor")]
        {
            let ep = bootstrap_client(_state_dir)?;
            deposit(&ep, via, &recipient_id, &blob).context("deposit failed")?;
            println!("sent to '{to_alias}' via {via} over Tor");
            return Ok(());
        }
        #[cfg(not(feature = "tor"))]
        anyhow::bail!("built without the `tor` feature");
    }
    deposit(&TcpTransport, via, &recipient_id, &blob).context("deposit failed")?;
    println!("sent to '{to_alias}' via {via} ({} bytes sealed)", blob.len());
    Ok(())
}

pub fn msg_collect(
    store: &Path,
    via: &str,
    use_tor: bool,
    _state_dir: Option<&Path>,
) -> Result<()> {
    let (_unlocked, profile) = open_store(store)?;
    let blobs = if use_tor {
        #[cfg(feature = "tor")]
        {
            let ep = bootstrap_client(_state_dir)?;
            collect(&ep, via, &profile.identity()?).context("collect failed")?
        }
        #[cfg(not(feature = "tor"))]
        anyhow::bail!("built without the `tor` feature");
    } else {
        collect(&TcpTransport, via, &profile.identity()?).context("collect failed")?
    };
    print_collected(&profile, &blobs);
    Ok(())
}

fn print_collected(profile: &Profile, blobs: &[Vec<u8>]) {
    if blobs.is_empty() {
        println!("(no messages)");
        return;
    }
    for blob in blobs {
        match open_message(profile, blob) {
            Ok(m) => {
                let who = profile
                    .contacts
                    .iter()
                    .find(|c| c.identity_pk().map(|k| k == m.sender_id).unwrap_or(false))
                    .map(|c| c.alias.clone())
                    .unwrap_or_else(|| "UNKNOWN sender".to_string());
                println!("[from {who}] {}", String::from_utf8_lossy(&m.plaintext));
            }
            Err(e) => eprintln!("[skipped an undecryptable/forged message: {e}]"),
        }
    }
}

#[cfg(feature = "tor")]
fn bootstrap_client(
    state_dir: Option<&Path>,
) -> Result<unichat_core::transport::tor::TorEndpoint> {
    use unichat_core::transport::tor::TorEndpoint;
    let state = state_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new("msg.tor-state").to_path_buf());
    std::fs::create_dir_all(&state).ok();
    std::fs::create_dir_all("msg.tor-cache").ok();
    println!("[tor] bootstrapping…");
    TorEndpoint::bootstrap(&state, Path::new("msg.tor-cache")).context("Tor bootstrap failed")
}
