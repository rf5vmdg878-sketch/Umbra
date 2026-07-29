//! `unichat group` / `unichat relay` — untrusted-relay group messaging (Phase 5).
//!
//! Tor build: relay/post/fetch run over direct TCP, or over Tor with `--tor`
//! (requires the `tor` cargo feature). Group management (create/join/list/leave)
//! is local and transport-independent.

use std::net::TcpListener;
use std::path::Path;
use std::thread;

use anyhow::{Context, Result};
use unichat_core::groups::relay::{fetch, post, GroupRelay};
use unichat_core::groups::{group_open, group_seal, Group};
use unichat_core::identity::Profile;
use unichat_core::transport::tcp::TcpTransport;

use crate::open_store;

#[cfg(feature = "tor")]
const RELAY_ONION_PORT: u16 = 9910;

pub fn relay_serve(bind: &str, use_tor: bool, _state_dir: Option<&Path>) -> Result<()> {
    let relay = GroupRelay::new();
    if use_tor {
        #[cfg(feature = "tor")]
        {
            use unichat_core::transport::tor::TorEndpoint;
            use unichat_core::transport::Listener;
            let state = _state_dir
                .map(Path::to_path_buf)
                .unwrap_or_else(|| Path::new("relay.tor-state").to_path_buf());
            std::fs::create_dir_all(&state).ok();
            std::fs::create_dir_all("relay.tor-cache").ok();
            println!("[tor] bootstrapping…");
            let ep = TorEndpoint::bootstrap(&state, Path::new("relay.tor-cache"))
                .context("Tor bootstrap failed")?;
            let listener = ep
                .listen("unichatrelay", RELAY_ONION_PORT)
                .context("onion launch failed")?;
            println!("group relay onion address: {}", listener.address()?);
            loop {
                match listener.accept() {
                    Ok(c) => {
                        let r = relay.clone();
                        thread::spawn(move || {
                            let _ = r.handle_connection(c);
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
    println!("group relay listening on {}", listener.local_addr()?);
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

pub fn post_msg(
    store: &Path,
    name: &str,
    via: &str,
    message: &str,
    use_tor: bool,
    _state_dir: Option<&Path>,
) -> Result<()> {
    let (_unlocked, profile) = open_store(store)?;
    let stored = profile
        .group(name)
        .with_context(|| format!("not a member of any group named '{name}'"))?;
    let group = Group::from_stored(stored)?;
    let blob = group_seal(&group, &profile.identity()?, message)?;

    let count = if use_tor {
        #[cfg(feature = "tor")]
        {
            let ep = bootstrap_client(_state_dir)?;
            post(&ep, via, group.group_id(), &blob).context("post failed")?
        }
        #[cfg(not(feature = "tor"))]
        anyhow::bail!("built without the `tor` feature");
    } else {
        post(&TcpTransport, via, group.group_id(), &blob).context("post failed")?
    };
    println!("posted to '{name}' via {via} (group now has {count} messages)");
    Ok(())
}

pub fn fetch_msgs(
    store: &Path,
    name: &str,
    via: &str,
    use_tor: bool,
    _state_dir: Option<&Path>,
) -> Result<()> {
    let (_unlocked, profile) = open_store(store)?;
    let stored = profile
        .group(name)
        .with_context(|| format!("not a member of any group named '{name}'"))?;
    let group = Group::from_stored(stored)?;

    let (blobs, _cursor) = if use_tor {
        #[cfg(feature = "tor")]
        {
            let ep = bootstrap_client(_state_dir)?;
            fetch(&ep, via, group.group_id(), 0).context("fetch failed")?
        }
        #[cfg(not(feature = "tor"))]
        anyhow::bail!("built without the `tor` feature");
    } else {
        fetch(&TcpTransport, via, group.group_id(), 0).context("fetch failed")?
    };
    print_group(&profile, &group, name, &blobs);
    Ok(())
}

fn print_group(profile: &Profile, group: &Group, name: &str, blobs: &[Vec<u8>]) {
    if blobs.is_empty() {
        println!("(no messages in '{name}')");
        return;
    }
    let my_id = profile
        .identity()
        .map(|i| i.public_bytes())
        .unwrap_or([0u8; 32]);
    for blob in blobs {
        match group_open(group, blob) {
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
}

#[cfg(feature = "tor")]
fn bootstrap_client(
    state_dir: Option<&Path>,
) -> Result<unichat_core::transport::tor::TorEndpoint> {
    use unichat_core::transport::tor::TorEndpoint;
    let state = state_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new("group.tor-state").to_path_buf());
    std::fs::create_dir_all(&state).ok();
    std::fs::create_dir_all("group.tor-cache").ok();
    println!("[tor] bootstrapping…");
    TorEndpoint::bootstrap(&state, Path::new("group.tor-cache")).context("Tor bootstrap failed")
}
