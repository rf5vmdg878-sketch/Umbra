//! `unichat mailbox` / `unichat msg` — offline store-and-forward (Phase 4).
//!
//! Direct-TCP transport (no-Tor fork). `mailbox serve` runs an untrusted
//! store-and-forward node; `msg send`/`msg collect` seal messages to a contact
//! and exchange them through a mailbox without both peers being online.

use std::net::TcpListener;
use std::path::Path;
use std::thread;

use anyhow::{Context, Result};
use unichat_core::sync::mailbox::{collect, deposit, MailboxStore};
use unichat_core::sync::{open_message, seal_message};
use unichat_core::transport::tcp::TcpTransport;

use crate::open_store;

/// Run a mailbox server until interrupted.
pub fn mailbox_serve(bind: &str) -> Result<()> {
    let store = MailboxStore::new();
    let listener = TcpListener::bind(bind).with_context(|| format!("cannot bind {bind}"))?;
    println!("mailbox listening on {}", listener.local_addr()?);
    println!("(untrusted store-and-forward: blobs are sealed; only owners can collect)");
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

/// Seal a message to a known contact and deposit it at a mailbox.
pub fn msg_send(store: &Path, to_alias: &str, via: &str, message: &str) -> Result<()> {
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
    deposit(&TcpTransport, via, &recipient_id, &blob)
        .with_context(|| format!("deposit at mailbox {via} failed"))?;
    println!("sent to '{to_alias}' via {via} ({} bytes sealed)", blob.len());
    Ok(())
}

/// Collect and decrypt offline messages addressed to us.
pub fn msg_collect(store: &Path, via: &str) -> Result<()> {
    let (_unlocked, profile) = open_store(store)?;
    let blobs = collect(&TcpTransport, via, &profile.identity()?)
        .with_context(|| format!("collect from mailbox {via} failed"))?;
    if blobs.is_empty() {
        println!("(no messages)");
        return Ok(());
    }
    for blob in &blobs {
        match open_message(&profile, blob) {
            Ok(m) => {
                // Map the authenticated sender to a known contact, if any.
                let who = profile
                    .contacts
                    .iter()
                    .find(|c| c.identity_pk().map(|k| k == m.sender_id).unwrap_or(false))
                    .map(|c| c.alias.clone())
                    .unwrap_or_else(|| "UNKNOWN sender".to_string());
                let text = String::from_utf8_lossy(&m.plaintext);
                println!("[from {who}] {text}");
            }
            Err(e) => eprintln!("[skipped an undecryptable/forged message: {e}]"),
        }
    }
    Ok(())
}
