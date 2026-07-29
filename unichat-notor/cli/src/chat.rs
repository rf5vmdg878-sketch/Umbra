//! `unichat chat` — 1:1 encrypted sessions over the transport (Phase 3).
//!
//! Scriptable demo surface: `serve` accepts one connection, applies the
//! knock/approve contact policy, then prints received chat lines and echoes an
//! ack; `send` dials a peer, optionally knocks, then sends message lines.

use std::io::Write;
use std::net::TcpStream;
use std::path::Path;

use anyhow::{bail, Context, Result};
use unichat_core::identity::ContactState;
use unichat_core::session::{
    initiator_handshake, responder_handshake, AppMsg, SecureChannel,
};
use unichat_core::transport::tcp::TcpListener;
use unichat_core::transport::Listener;

use crate::open_store;

/// `chat serve`: listen, accept one session, run the contact policy, print
/// received messages.
pub fn serve(store: &Path, bind: &str, accept_unknown: bool) -> Result<()> {
    let (unlocked, mut profile) = open_store(store)?;
    let listener = TcpListener::bind(bind).context("failed to bind")?;
    println!("listening on {}", listener.address()?);
    println!("your address to share: {bind}  (fingerprint {})", profile.fingerprint()?);

    let conn = listener.accept().context("accept failed")?;
    let identity = profile.identity()?;
    let xwing = profile.xwing()?;
    let mut ch = responder_handshake(conn, &identity, &xwing)
        .context("handshake failed")?;
    let peer_id = *ch.peer_identity();

    // Is the authenticated peer a known, approved contact?
    let known = profile.contacts.iter().find(|c| {
        c.identity_pk().map(|k| k == peer_id).unwrap_or(false)
            && c.state == ContactState::Approved
    });

    if let Some(c) = known {
        println!("[session] known contact '{}' connected", c.alias);
    } else {
        // Unknown peer: only a single contact request is allowed through.
        match ch.recv()? {
            Some(AppMsg::ContactRequest {
                nickname,
                text,
                bundle,
            }) => {
                let verified = ch
                    .verify_peer_bundle(&bundle)
                    .context("contact request bundle failed verification")?;
                println!(
                    "[knock] '{nickname}' ({}) says: {text}",
                    verified.fingerprint()
                );
                if accept_unknown {
                    let alias = sanitize_alias(&nickname);
                    profile.add_contact(&alias, &verified).ok();
                    unlocked.save(&profile)?;
                    ch.send(&AppMsg::ContactResponse {
                        accepted: true,
                        bundle: Some(profile.bundle()?.encode()),
                    })?;
                    println!("[knock] auto-approved as contact '{alias}'");
                } else {
                    ch.send(&AppMsg::ContactResponse {
                        accepted: false,
                        bundle: None,
                    })?;
                    println!("[knock] rejected (pass --accept-unknown to approve)");
                    return Ok(());
                }
            }
            _ => bail!("unknown peer did not send a contact request"),
        }
    }

    run_echo_loop(&mut ch)
}

/// Receive chat messages, print them, ack each, until the peer says Bye or
/// disconnects.
fn run_echo_loop<S: std::io::Read + std::io::Write>(
    ch: &mut SecureChannel<S>,
) -> Result<()> {
    loop {
        match ch.recv()? {
            Some(AppMsg::Chat { id, text }) => {
                println!("<peer> {text}");
                std::io::stdout().flush().ok();
                ch.send(&AppMsg::ChatAck { id })?;
            }
            Some(AppMsg::Bye) | None => {
                println!("[session] closed");
                return Ok(());
            }
            Some(other) => println!("[session] ignoring unexpected message: {other:?}"),
        }
    }
}

/// `chat send`: dial a peer, optionally knock, then send message lines.
pub fn send(
    store: &Path,
    to: &str,
    knock: Option<&str>,
    messages: &[String],
) -> Result<()> {
    let (unlocked, mut profile) = open_store(store)?;
    let stream = TcpStream::connect(to).with_context(|| format!("cannot connect to {to}"))?;
    let identity = profile.identity()?;
    let xwing = profile.xwing()?;
    let mut ch = initiator_handshake(stream, &identity, &xwing)
        .context("handshake failed")?;
    println!("[session] connected; peer authenticated");

    if let Some(nickname) = knock {
        ch.send(&AppMsg::ContactRequest {
            nickname: nickname.to_string(),
            text: "contact request".into(),
            bundle: profile.bundle()?.encode(),
        })?;
        match ch.recv()? {
            Some(AppMsg::ContactResponse {
                accepted: true,
                bundle,
            }) => {
                println!("[knock] accepted");
                if let Some(b) = bundle {
                    if let Ok(v) = ch.verify_peer_bundle(&b) {
                        // Alias the peer by a stable prefix of their
                        // fingerprint (we don't know their display name).
                        let fp = v.fingerprint();
                        let alias = format!("peer-{}", &fp[..fp.find('-').unwrap_or(8)]);
                        if profile.add_contact(&alias, &v).is_ok() {
                            unlocked.save(&profile)?;
                            println!("[knock] saved peer as contact '{alias}'");
                        }
                    }
                }
            }
            Some(AppMsg::ContactResponse { accepted: false, .. }) => {
                bail!("contact request was rejected");
            }
            _ => bail!("unexpected response to contact request"),
        }
    }

    for (i, m) in messages.iter().enumerate() {
        let id = i as u32 + 1;
        ch.send(&AppMsg::Chat {
            id,
            text: m.clone(),
        })?;
        match ch.recv()? {
            Some(AppMsg::ChatAck { id: ack }) if ack == id => println!("[ack] {m}"),
            other => println!("[warn] unexpected ack: {other:?}"),
        }
    }
    ch.send(&AppMsg::Bye)?;
    Ok(())
}

fn sanitize_alias(nickname: &str) -> String {
    let a: String = nickname
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == ' ')
        .take(30)
        .collect();
    let a = a.trim().to_string();
    if a.is_empty() {
        "peer".into()
    } else {
        a
    }
}
