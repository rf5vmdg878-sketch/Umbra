//! `unichat group` / `unichat relay` — untrusted-relay group messaging (Phase 5).
//!
//! Direct-TCP transport (no-Tor fork). `relay serve` runs a dumb group relay;
//! `group create/join/list/leave` manage membership; `group post/fetch` send
//! and read messages through a relay.

use std::net::TcpListener;
use std::path::Path;
use std::thread;

use anyhow::{Context, Result};
use unichat_core::groups::relay::{fetch, post, GroupRelay};
use unichat_core::groups::{group_open, group_seal, Group};
use unichat_core::transport::tcp::TcpTransport;

use crate::open_store;

pub fn relay_serve(bind: &str) -> Result<()> {
    let relay = GroupRelay::new();
    let listener = TcpListener::bind(bind).with_context(|| format!("cannot bind {bind}"))?;
    println!("group relay listening on {}", listener.local_addr()?);
    println!("(untrusted: stores sealed group blobs; cannot read them)");
    for conn in listener.incoming() {
        match conn {
            Ok(c) => {
                let r = relay.clone();
                thread::spawn(move || {
                    let _ = r.handle_connection(c);
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

pub fn create(store: &Path, name: &str) -> Result<()> {
    let (unlocked, mut profile) = open_store(store)?;
    let group = Group::create(name);
    profile.add_group(group.to_stored())?;
    unlocked.save(&profile)?;
    println!("created group '{name}'");
    println!("\nInvite (share ONLY over a secure channel — it grants membership):");
    println!("{}", group.descriptor());
    Ok(())
}

pub fn join(store: &Path, descriptor: &str) -> Result<()> {
    let (unlocked, mut profile) = open_store(store)?;
    let group = Group::from_descriptor(descriptor).context("invalid group descriptor")?;
    let name = group.name.clone();
    profile.add_group(group.to_stored())?;
    unlocked.save(&profile)?;
    println!("joined group '{name}'");
    Ok(())
}

pub fn list(store: &Path) -> Result<()> {
    let (_unlocked, profile) = open_store(store)?;
    if profile.groups.is_empty() {
        println!("(no groups)");
        return Ok(());
    }
    for g in &profile.groups {
        println!("{:<24} id {}", g.name, &g.group_id_b64[..12.min(g.group_id_b64.len())]);
    }
    Ok(())
}

pub fn leave(store: &Path, name: &str) -> Result<()> {
    let (unlocked, mut profile) = open_store(store)?;
    if !profile.remove_group(name) {
        anyhow::bail!("no group named '{name}'");
    }
    unlocked.save(&profile)?;
    println!("left group '{name}'");
    Ok(())
}

pub fn post_msg(store: &Path, name: &str, via: &str, message: &str) -> Result<()> {
    let (_unlocked, profile) = open_store(store)?;
    let stored = profile
        .group(name)
        .with_context(|| format!("not a member of any group named '{name}'"))?;
    let group = Group::from_stored(stored)?;
    let blob = group_seal(&group, &profile.identity()?, message)?;
    let count = post(&TcpTransport, via, group.group_id(), &blob)
        .with_context(|| format!("post to relay {via} failed"))?;
    println!("posted to '{name}' via {via} (group now has {count} messages)");
    Ok(())
}

pub fn fetch_msgs(store: &Path, name: &str, via: &str) -> Result<()> {
    let (_unlocked, profile) = open_store(store)?;
    let stored = profile
        .group(name)
        .with_context(|| format!("not a member of any group named '{name}'"))?;
    let group = Group::from_stored(stored)?;
    let my_id = profile.identity()?.public_bytes();

    let (blobs, _cursor) = fetch(&TcpTransport, via, group.group_id(), 0)
        .with_context(|| format!("fetch from relay {via} failed"))?;
    if blobs.is_empty() {
        println!("(no messages in '{name}')");
        return Ok(());
    }
    for blob in &blobs {
        match group_open(&group, blob) {
            Ok(m) => {
                let who = if m.sender_id == my_id {
                    "me".to_string()
                } else {
                    profile
                        .contacts
                        .iter()
                        .find(|c| c.identity_pk().map(|k| k == m.sender_id).unwrap_or(false))
                        .map(|c| c.alias.clone())
                        .unwrap_or_else(|| {
                            let fp: String =
                                m.sender_id[..4].iter().map(|b| format!("{b:02x}")).collect();
                            format!("member#{fp}")
                        })
                };
                println!("[{name}] <{who}> {}", m.body);
            }
            Err(_) => eprintln!("[{name}] (skipped an undecryptable/forged message)"),
        }
    }
    Ok(())
}
