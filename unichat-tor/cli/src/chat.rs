//! `unichat chat` — 1:1 encrypted sessions (Phase 3), Tor build.
//!
//! The session policy and message loop are generic over the byte stream, so
//! the same code runs over direct TCP or, with `--tor` (requires the `tor`
//! cargo feature), over a Tor v3 onion service via arti.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

use anyhow::{bail, Context, Result};
use unichat_core::identity::ContactState;
use unichat_core::session::{
    initiator_handshake, responder_handshake, AppMsg, SecureChannel,
};
use unichat_core::storage::UnlockedStore;
use unichat_core::transport::tcp::TcpListener;
use unichat_core::transport::Listener;

use crate::open_store;

/// Virtual port used for onion-service sessions.
#[cfg(feature = "tor")]
const ONION_PORT: u16 = 9878;

pub fn serve(
    store: &Path,
    bind: &str,
    accept_unknown: bool,
    use_tor: bool,
    _state_dir: Option<&Path>,
) -> Result<()> {
    let (unlocked, profile) = open_store(store)?;
    let identity = profile.identity()?;
    let xwing = profile.xwing()?;

    if use_tor {
        #[cfg(feature = "tor")]
        {
            use unichat_core::transport::tor::TorEndpoint;
            let state = _state_dir
                .map(Path::to_path_buf)
                .unwrap_or_else(|| store.with_extension("tor-state"));
            let cache = store.with_extension("tor-cache");
            std::fs::create_dir_all(&state).ok();
            std::fs::create_dir_all(&cache).ok();
            println!("[tor] bootstrapping (this can take a minute)…");
            let ep = TorEndpoint::bootstrap(&state, &cache).context("Tor bootstrap failed")?;
            let listener = ep.listen("unichat", ONION_PORT).context("onion launch failed")?;
            println!("your onion address: {}", listener.address()?);
            println!("fingerprint: {}", profile.fingerprint()?);
            let conn = listener.accept().context("accept failed")?;
            let ch = responder_handshake(conn, &identity, &xwing).context("handshake failed")?;
            return handle_responder(ch, unlocked, profile, accept_unknown);
        }
        #[cfg(not(feature = "tor"))]
        bail!("this binary was built without the `tor` feature (rebuild with --features tor)");
    }

    let listener = TcpListener::bind(bind).context("failed to bind")?;
    println!("listening on {}", listener.address()?);
    println!("fingerprint: {}", profile.fingerprint()?);
    let conn = listener.accept().context("accept failed")?;
    let ch = responder_handshake(conn, &identity, &xwing).context("handshake failed")?;
    handle_responder(ch, unlocked, profile, accept_unknown)
}

pub fn send(
    store: &Path,
    to: &str,
    knock: Option<&str>,
    messages: &[String],
    use_tor: bool,
    _state_dir: Option<&Path>,
) -> Result<()> {
    let (unlocked, profile) = open_store(store)?;
    let identity = profile.identity()?;
    let xwing = profile.xwing()?;

    if use_tor {
        #[cfg(feature = "tor")]
        {
            use unichat_core::transport::tor::TorEndpoint;
            use unichat_core::transport::Transport as _;
            let state = _state_dir
                .map(Path::to_path_buf)
                .unwrap_or_else(|| store.with_extension("tor-state"));
            let cache = store.with_extension("tor-cache");
            std::fs::create_dir_all(&state).ok();
            std::fs::create_dir_all(&cache).ok();
            println!("[tor] bootstrapping (this can take a minute)…");
            let ep = TorEndpoint::bootstrap(&state, &cache).context("Tor bootstrap failed")?;
            let conn = ep.dial(to).with_context(|| format!("cannot connect to {to}"))?;
            let ch = initiator_handshake(conn, &identity, &xwing).context("handshake failed")?;
            println!("[session] connected over Tor; peer authenticated");
            return handle_initiator(ch, unlocked, profile, knock, messages);
        }
        #[cfg(not(feature = "tor"))]
        bail!("this binary was built without the `tor` feature (rebuild with --features tor)");
    }

    let stream = TcpStream::connect(to).with_context(|| format!("cannot connect to {to}"))?;
    let ch = initiator_handshake(stream, &identity, &xwing).context("handshake failed")?;
    println!("[session] connected; peer authenticated");
    handle_initiator(ch, unlocked, profile, knock, messages)
}

/// Responder policy + echo loop (transport-agnostic).
fn handle_responder<S: Read + Write>(
    mut ch: SecureChannel<S>,
    unlocked: UnlockedStore,
    mut profile: unichat_core::identity::Profile,
    accept_unknown: bool,
) -> Result<()> {
    let peer_id = *ch.peer_identity();
    let known = profile.contacts.iter().find(|c| {
        c.identity_pk().map(|k| k == peer_id).unwrap_or(false)
            && c.state == ContactState::Approved
    });

    if let Some(c) = known {
        println!("[session] known contact '{}' connected", c.alias);
    } else {
        match ch.recv()? {
            Some(AppMsg::ContactRequest {
                nickname,
                text,
                bundle,
            }) => {
                let verified = ch
                    .verify_peer_bundle(&bundle)
                    .context("contact request bundle failed verification")?;
                println!("[knock] '{nickname}' ({}) says: {text}", verified.fingerprint());
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
            Some(other) => println!("[session] ignoring: {other:?}"),
        }
    }
}

/// Initiator: optional knock, then send messages (transport-agnostic).
fn handle_initiator<S: Read + Write>(
    mut ch: SecureChannel<S>,
    unlocked: UnlockedStore,
    mut profile: unichat_core::identity::Profile,
    knock: Option<&str>,
    messages: &[String],
) -> Result<()> {
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
                bail!("contact request was rejected")
            }
            _ => bail!("unexpected response to contact request"),
        }
    }

    for (i, m) in messages.iter().enumerate() {
        let id = i as u32 + 1;
        ch.send(&AppMsg::Chat { id, text: m.clone() })?;
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
