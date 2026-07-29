//! `unichat call` — E2E encrypted file transfer and voice/video calls routed
//! through an untrusted relay (umbra-relay's call service). Two parties meet on
//! the relay by a shared call-id, run the post-quantum session handshake over
//! the relayed pipe, then transfer files / stream media — the relay only ever
//! sees ciphertext.
//!
//! With the `media` feature (default) `dial`/`answer` capture the real
//! microphone/camera and play received audio via `unichat-media`; without it
//! they exercise the encrypted media path with synthetic frames. Either way the
//! relay only ever sees ciphertext.

use std::path::Path;
#[cfg(not(feature = "media"))]
use std::time::Duration;

use anyhow::{Context, Result};
use unichat_core::call::rendezvous;
#[cfg(not(feature = "media"))]
use unichat_core::call::{MediaKind, SecureMediaChannel};
use unichat_core::session::{initiator_handshake, responder_handshake, SecureChannel};
use unichat_core::transport::tcp::TcpTransport;
use unichat_core::xfer::{recv_file, send_file};

use crate::open_store;

fn id_bytes(call_id: &str) -> Vec<u8> {
    call_id.as_bytes().to_vec()
}

/// Caller: rendezvous + PQ handshake, then run `f` with the established channel.
fn as_caller<F, R>(store: &Path, relay: &str, call_id: &str, f: F) -> Result<R>
where
    F: FnOnce(SecureChannel<std::net::TcpStream>) -> Result<R>,
{
    let (_u, profile) = open_store(store)?;
    let conn = rendezvous(&TcpTransport, relay, &id_bytes(call_id), true)
        .with_context(|| format!("reaching relay {relay}"))?;
    println!("[call] on relay {relay} as caller (id={call_id}); waiting for peer...");
    let ch = initiator_handshake(conn, &profile.identity()?, &profile.xwing()?)
        .context("secure handshake failed")?;
    println!("[session] connected E2E; peer authenticated");
    f(ch)
}

fn as_callee<F, R>(store: &Path, relay: &str, call_id: &str, f: F) -> Result<R>
where
    F: FnOnce(SecureChannel<std::net::TcpStream>) -> Result<R>,
{
    let (_u, profile) = open_store(store)?;
    let conn = rendezvous(&TcpTransport, relay, &id_bytes(call_id), false)
        .with_context(|| format!("reaching relay {relay}"))?;
    println!("[call] on relay {relay} as callee (id={call_id}); waiting for peer...");
    let ch = responder_handshake(conn, &profile.identity()?, &profile.xwing()?)
        .context("secure handshake failed")?;
    println!("[session] connected E2E; peer authenticated");
    f(ch)
}

pub fn send_file_cmd(store: &Path, relay: &str, call_id: &str, file: &Path) -> Result<()> {
    let data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    as_caller(store, relay, call_id, |mut ch| {
        if send_file(&mut ch, &name, &data)? {
            println!("sent '{name}' ({} bytes) E2E through the relay", data.len());
        } else {
            println!("peer declined the file");
        }
        Ok(())
    })
}

pub fn recv_file_cmd(store: &Path, relay: &str, call_id: &str, out_dir: &Path) -> Result<()> {
    as_callee(store, relay, call_id, |mut ch| {
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
    })
}

#[cfg(not(feature = "media"))]
fn synth_audio(i: u32) -> Vec<u8> {
    // Stand-in for an Opus frame (~20ms). Real audio comes from a MediaSource.
    let mut v = vec![0u8; 160];
    v[0..4].copy_from_slice(&i.to_le_bytes());
    v
}
#[cfg(not(feature = "media"))]
fn synth_video(i: u32) -> Vec<u8> {
    let mut v = vec![0u8; 1024];
    v[0..4].copy_from_slice(&i.to_le_bytes());
    v
}

/// Run a live call with the real mic/camera/speaker. `max_secs` bounds the
/// caller; `None` (callee) runs until the peer hangs up. Incoming video is
/// decoded but dropped (the CLI has no display); audio plays on the speaker.
#[cfg(feature = "media")]
fn run_media_call(
    stream: std::net::TcpStream,
    secret: [u8; 32],
    caller: bool,
    video: bool,
    max_secs: Option<u32>,
) {
    use std::sync::Arc;
    let status: Arc<dyn Fn(String) + Send + Sync> = Arc::new(|m: String| println!("[call] {m}"));
    let handle = match unichat_media::run_call(stream, secret, caller, video, None, status) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[call] media error: {e}");
            return;
        }
    };
    println!(
        "[call] live — {} (hang up with Ctrl-C)",
        if video { "voice + video" } else { "voice" }
    );
    let start = std::time::Instant::now();
    loop {
        if handle.ended() {
            break;
        }
        if let Some(s) = max_secs {
            if start.elapsed().as_secs() >= s as u64 {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    handle.hang_up();
    println!("[call] ended");
}

pub fn dial(store: &Path, relay: &str, call_id: &str, video: bool, seconds: u32) -> Result<()> {
    as_caller(store, relay, call_id, |ch| {
        let secret = ch.call_secret().clone();
        let caller = ch.is_initiator();
        let stream = ch.into_inner();
        #[cfg(feature = "media")]
        run_media_call(stream, *secret, caller, video, Some(seconds));
        #[cfg(not(feature = "media"))]
        {
            let mut media = SecureMediaChannel::new(stream, &secret, caller)?;
            let frames = seconds.max(1) * 50; // ~50 fps
            println!(
                "[call] streaming synthetic {} for {seconds}s ({frames} audio frames)...",
                if video { "voice + video" } else { "voice" }
            );
            for i in 0..frames {
                media.send(MediaKind::Audio, i, &synth_audio(i))?;
                if video {
                    media.send(MediaKind::Video, i, &synth_video(i))?;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            println!("[call] done — {frames} audio{} frames sent E2E", if video { " + video" } else { "" });
        }
        Ok(())
    })
}

pub fn answer(store: &Path, relay: &str, call_id: &str) -> Result<()> {
    as_callee(store, relay, call_id, |ch| {
        let secret = ch.call_secret().clone();
        let caller = ch.is_initiator();
        let stream = ch.into_inner();
        #[cfg(feature = "media")]
        run_media_call(stream, *secret, caller, false, None);
        #[cfg(not(feature = "media"))]
        {
            let mut media = SecureMediaChannel::new(stream, &secret, caller)?;
            println!("[call] connected; receiving encrypted media (Ctrl-C to hang up)...");
            let (mut a, mut v) = (0u64, 0u64);
            while let Some(f) = media.recv()? {
                match f.kind {
                    MediaKind::Audio => a += 1,
                    MediaKind::Video => v += 1,
                }
            }
            println!("[call] ended — decrypted {a} audio + {v} video frames, all authenticated");
        }
        Ok(())
    })
}
