//! `unichat call` — E2E file transfer + voice/video calls through a relay.
//! Tor build: runs over TCP, or over Tor with `--tor` (the whole flow is
//! generic over the stream, so the onion path works unchanged). Media is
//! synthetic until a real capture/codec layer is wired into
//! `unichat_core::call::{MediaSource, MediaSink}`.

use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use unichat_core::call::{rendezvous, MediaKind, SecureMediaChannel};
use unichat_core::identity::Profile;
use unichat_core::session::{initiator_handshake, responder_handshake};
use unichat_core::transport::tcp::TcpTransport;
use unichat_core::xfer::{recv_file, send_file};

use crate::open_store;

fn id_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

// --- generic actions over any established connection stream ---

fn run_send_file<C: Read + Write>(conn: C, profile: &Profile, name: &str, data: &[u8]) -> Result<()> {
    let mut ch = initiator_handshake(conn, &profile.identity()?, &profile.xwing()?)
        .context("secure handshake failed")?;
    println!("[session] connected E2E; peer authenticated");
    if send_file(&mut ch, name, data)? {
        println!("sent '{name}' ({} bytes) E2E through the relay", data.len());
    } else {
        println!("peer declined the file");
    }
    Ok(())
}

fn run_recv_file<C: Read + Write>(conn: C, profile: &Profile, out_dir: &Path) -> Result<()> {
    let mut ch = responder_handshake(conn, &profile.identity()?, &profile.xwing()?)
        .context("secure handshake failed")?;
    println!("[session] connected E2E; peer authenticated");
    match recv_file(&mut ch, true)? {
        Some((name, data)) => {
            std::fs::create_dir_all(out_dir).ok();
            let safe: String = name
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("file")
                .chars()
                .filter(|c| !c.is_control() && !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
                .collect();
            let path = out_dir.join(if safe.is_empty() { "file".into() } else { safe });
            std::fs::write(&path, &data)?;
            println!("received '{}' ({} bytes) -> {}", name, data.len(), path.display());
        }
        None => println!("no file received"),
    }
    Ok(())
}

fn synth(n: usize, i: u32) -> Vec<u8> {
    let mut v = vec![0u8; n];
    v[0..4].copy_from_slice(&i.to_le_bytes());
    v
}

fn run_dial<C: Read + Write>(conn: C, profile: &Profile, video: bool, seconds: u32) -> Result<()> {
    let ch = initiator_handshake(conn, &profile.identity()?, &profile.xwing()?)
        .context("secure handshake failed")?;
    println!("[session] connected E2E; peer authenticated");
    let secret = ch.call_secret().clone();
    let caller = ch.is_initiator();
    let mut media = SecureMediaChannel::new(ch.into_inner(), &secret, caller)?;
    let frames = seconds.max(1) * 50;
    println!("[call] streaming synthetic {} ({frames} frames)...", if video { "voice+video" } else { "voice" });
    for i in 0..frames {
        media.send(MediaKind::Audio, i, &synth(160, i))?;
        if video {
            media.send(MediaKind::Video, i, &synth(1024, i))?;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    println!("[call] done — {frames} audio{} frames sent E2E", if video { " + video" } else { "" });
    Ok(())
}

fn run_answer<C: Read + Write>(conn: C, profile: &Profile) -> Result<()> {
    let ch = responder_handshake(conn, &profile.identity()?, &profile.xwing()?)
        .context("secure handshake failed")?;
    println!("[session] connected E2E; peer authenticated");
    let secret = ch.call_secret().clone();
    let caller = ch.is_initiator();
    let mut media = SecureMediaChannel::new(ch.into_inner(), &secret, caller)?;
    println!("[call] receiving encrypted media...");
    let (mut a, mut v) = (0u64, 0u64);
    while let Some(f) = media.recv()? {
        match f.kind {
            MediaKind::Audio => a += 1,
            MediaKind::Video => v += 1,
        }
    }
    println!("[call] ended — decrypted {a} audio + {v} video frames, all authenticated");
    Ok(())
}

// --- transport dispatch: TCP, or Tor (feature-gated) ---

#[cfg(feature = "tor")]
fn tor_endpoint(state_dir: Option<&Path>) -> Result<unichat_core::transport::tor::TorEndpoint> {
    use unichat_core::transport::tor::TorEndpoint;
    let state = state_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new("call.tor-state").to_path_buf());
    std::fs::create_dir_all(&state).ok();
    std::fs::create_dir_all("call.tor-cache").ok();
    println!("[tor] bootstrapping…");
    TorEndpoint::bootstrap(&state, Path::new("call.tor-cache")).context("Tor bootstrap failed")
}

macro_rules! dispatch {
    ($relay:expr, $id:expr, $caller:expr, $use_tor:expr, $state:expr, $run:expr) => {{
        let cid = id_bytes($id);
        let _ = &$state; // used only in the tor branch

        if $use_tor {
            #[cfg(feature = "tor")]
            {
                let ep = tor_endpoint($state)?;
                let conn = rendezvous(&ep, $relay, &cid, $caller)
                    .with_context(|| format!("reaching relay {}", $relay))?;
                $run(conn)
            }
            #[cfg(not(feature = "tor"))]
            {
                anyhow::bail!("built without the `tor` feature (rebuild with --features tor)")
            }
        } else {
            let conn = rendezvous(&TcpTransport, $relay, &cid, $caller)
                .with_context(|| format!("reaching relay {}", $relay))?;
            $run(conn)
        }
    }};
}

pub fn send_file_cmd(store: &Path, relay: &str, id: &str, file: &Path, tor: bool, state: Option<&Path>) -> Result<()> {
    let (_u, profile) = open_store(store)?;
    let data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
    println!("[call] rendezvous as caller (id={id})");
    dispatch!(relay, id, true, tor, state, |c| run_send_file(c, &profile, &name, &data))
}

pub fn recv_file_cmd(store: &Path, relay: &str, id: &str, out: &Path, tor: bool, state: Option<&Path>) -> Result<()> {
    let (_u, profile) = open_store(store)?;
    println!("[call] rendezvous as callee (id={id})");
    dispatch!(relay, id, false, tor, state, |c| run_recv_file(c, &profile, out))
}

pub fn dial(store: &Path, relay: &str, id: &str, video: bool, seconds: u32, tor: bool, state: Option<&Path>) -> Result<()> {
    let (_u, profile) = open_store(store)?;
    println!("[call] dialing (id={id})");
    dispatch!(relay, id, true, tor, state, |c| run_dial(c, &profile, video, seconds))
}

pub fn answer(store: &Path, relay: &str, id: &str, tor: bool, state: Option<&Path>) -> Result<()> {
    let (_u, profile) = open_store(store)?;
    println!("[call] answering (id={id})");
    dispatch!(relay, id, false, tor, state, |c| run_answer(c, &profile))
}
