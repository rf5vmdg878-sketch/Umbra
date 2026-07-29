//! Background engine: owns the unlocked profile and runs every core operation
//! off the UI thread. The window sends [`Command`]s and receives [`Event`]s over
//! channels, so a Tor bootstrap or a network round-trip never freezes the frame.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use zeroize::Zeroizing;

use unichat_core::groups::relay;
use unichat_core::groups::{group_open, group_seal, Group};
use unichat_core::crypto::xwing::XWingPrivate;
use unichat_core::identity::{ContactState, Identity, KeyBundle, Profile};
use unichat_core::storage::UnlockedStore;
use unichat_core::sync::mailbox;
use unichat_core::sync::{open_message, seal_message};
use unichat_core::transport::tcp::{TcpListener, TcpTransport};
use unichat_core::transport::Listener;

#[derive(Clone, Copy, PartialEq)]
pub enum Level {
    Info,
    Good,
    Warn,
    Bad,
}

#[derive(Clone)]
pub struct ContactView {
    pub alias: String,
    pub fingerprint: String,
    pub verified: bool,
    pub state: String,
}

#[derive(Clone)]
pub struct GroupView {
    pub name: String,
    pub descriptor: String,
}

#[derive(Clone)]
pub struct MessageView {
    pub who: String,
    pub body: String,
    pub mine: bool,
    pub unknown: bool,
    pub ts: u64,
}

#[derive(Clone)]
pub struct ProfileView {
    pub name: String,
    pub fingerprint: String,
    pub bundle: String,
    pub kdf: String,
}

/// Messages from the UI to the engine.
pub enum Command {
    CreateProfile {
        path: PathBuf,
        name: String,
        passphrase: Zeroizing<String>,
    },
    Unlock {
        path: PathBuf,
        passphrase: Zeroizing<String>,
    },
    Lock,
    ChangePassphrase {
        new: Zeroizing<String>,
    },
    AddContact {
        alias: String,
        bundle: String,
    },
    SetVerified {
        alias: String,
        verified: bool,
    },
    RemoveContact {
        alias: String,
    },
    CreateGroup {
        name: String,
    },
    JoinGroup {
        descriptor: String,
    },
    LeaveGroup {
        name: String,
    },
    GroupPost {
        group: String,
        relay: String,
        text: String,
    },
    GroupFetch {
        group: String,
        relay: String,
    },
    MsgSend {
        alias: String,
        mailbox: String,
        text: String,
    },
    MsgCollect {
        mailbox: String,
    },
    StartMailbox {
        bind: String,
    },
    StartRelay {
        bind: String,
    },
    CallSendFile {
        relay: String,
        id: String,
        file: PathBuf,
    },
    CallRecvFile {
        relay: String,
        id: String,
        out_dir: PathBuf,
    },
    CallDial {
        relay: String,
        id: String,
        video: bool,
        seconds: u32,
    },
    CallAnswer {
        relay: String,
        id: String,
        video: bool,
    },
    SetUseTor(bool),
    /// Securely purge app state back to installed defaults (maintenance/security).
    Sanitize {
        store: String,
        profiles: bool,
        tor: bool,
    },
}

/// Messages from the engine to the UI.
pub enum Event {
    Status(String, Level),
    Unlocked(ProfileView),
    Locked,
    Contacts(Vec<ContactView>),
    Groups(Vec<GroupView>),
    /// Full re-render of a group thread (already deduped + sorted).
    GroupThread {
        group: String,
        messages: Vec<MessageView>,
    },
    Inbox(Vec<MessageView>),
    ServerUp {
        kind: String,
        addr: String,
    },
    /// A decoded incoming video frame (RGBA) from a live call, for display.
    VideoFrame {
        width: u32,
        height: u32,
        rgba: Vec<u8>,
    },
    /// The live call finished (peer hung up, duration elapsed, or error).
    CallEnded,
}

struct Session {
    store: UnlockedStore,
    profile: Profile,
    /// Fetch cursors + seen ids per group (replay dedup — security review M1).
    group_cursor: HashMap<String, usize>,
    group_seen: HashMap<String, HashSet<[u8; 16]>>,
    group_thread: HashMap<String, Vec<MessageView>>,
    inbox: Vec<MessageView>,
    inbox_seen: HashSet<[u8; 16]>,
    use_tor: bool,
}

// On lock (Command::Lock drops the session) or clean engine shutdown, stop Tor
// and re-encrypt its state back into the vault, wiping the plaintext dir.
#[cfg(feature = "tor")]
impl Drop for Session {
    fn drop(&mut self) {
        crate::tor_ep::shutdown();
        crate::tor_ep::persist_state(&self.store);
    }
}

pub struct EngineHandle {
    pub tx: Sender<Command>,
    pub rx: Receiver<Event>,
}

/// Spawn the engine thread. Returns channels to talk to it.
pub fn spawn() -> EngineHandle {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<Command>();
    let (evt_tx, evt_rx) = std::sync::mpsc::channel::<Event>();
    thread::spawn(move || run(cmd_rx, evt_tx));
    EngineHandle {
        tx: cmd_tx,
        rx: evt_rx,
    }
}

fn run(cmd_rx: Receiver<Command>, evt: Sender<Event>) {
    let mut session: Option<Session> = None;
    while let Ok(cmd) = cmd_rx.recv() {
        handle(cmd, &mut session, &evt);
    }
}

fn status(evt: &Sender<Event>, msg: impl Into<String>, level: Level) {
    let _ = evt.send(Event::Status(msg.into(), level));
}

fn contact_views(profile: &Profile) -> Vec<ContactView> {
    profile
        .contacts
        .iter()
        .map(|c| ContactView {
            alias: c.alias.clone(),
            fingerprint: c.fingerprint().unwrap_or_else(|_| "<corrupt>".into()),
            verified: c.verified,
            state: format!("{:?}", c.state).to_lowercase(),
        })
        .collect()
}

fn group_views(profile: &Profile) -> Vec<GroupView> {
    profile
        .groups
        .iter()
        .map(|g| GroupView {
            name: g.name.clone(),
            descriptor: Group::from_stored(g)
                .map(|gr| gr.descriptor())
                .unwrap_or_default(),
        })
        .collect()
}

fn push_state(session: &Session, evt: &Sender<Event>) {
    let _ = evt.send(Event::Contacts(contact_views(&session.profile)));
    let _ = evt.send(Event::Groups(group_views(&session.profile)));
}

fn handle(cmd: Command, session: &mut Option<Session>, evt: &Sender<Event>) {
    match cmd {
        Command::CreateProfile {
            path,
            name,
            passphrase,
        } => {
            let profile = match Profile::create(&name) {
                Ok(p) => p,
                Err(e) => return status(evt, format!("create failed: {e}"), Level::Bad),
            };
            let pass = Zeroizing::new(passphrase.as_bytes().to_vec());
            match UnlockedStore::create(&path, &pass, &profile) {
                Ok(store) => {
                    open_session(session, store, profile, evt);
                    status(evt, "profile created", Level::Good);
                }
                Err(e) => status(evt, format!("create failed: {e}"), Level::Bad),
            }
        }
        Command::Unlock { path, passphrase } => {
            let pass = Zeroizing::new(passphrase.as_bytes().to_vec());
            match UnlockedStore::open(&path, &pass) {
                Ok((store, profile)) => {
                    open_session(session, store, profile, evt);
                    status(evt, "unlocked", Level::Good);
                }
                Err(e) => status(evt, format!("unlock failed: {e}"), Level::Bad),
            }
        }
        Command::Lock => {
            *session = None;
            let _ = evt.send(Event::Locked);
            status(evt, "locked", Level::Info);
        }
        Command::SetUseTor(on) => {
            if let Some(s) = session {
                s.use_tor = on;
            }
            status(
                evt,
                if on {
                    "routing over Tor"
                } else {
                    "routing over direct TCP"
                },
                Level::Info,
            );
        }
        Command::StartMailbox { bind } => spawn_mailbox(&bind, evt),
        Command::StartRelay { bind } => spawn_relay(&bind, evt),
        Command::Sanitize { store, profiles, tor } => {
            // Lock first (drops the session), then securely wipe the selection.
            *session = None;
            let mut targets = Vec::new();
            if profiles {
                targets.extend(unichat_core::sanitize::profile_targets(std::path::Path::new(&store)));
            }
            if tor {
                targets.extend(unichat_core::sanitize::tor_targets());
            }
            let report = unichat_core::sanitize::purge(&targets);
            let _ = evt.send(Event::Locked);
            status(
                evt,
                format!(
                    "sanitized: removed {} item(s), ~{} KB — reset to installed defaults",
                    report.removed_count(),
                    report.total_bytes() / 1024
                ),
                Level::Good,
            );
        }
        other => {
            let Some(s) = session.as_mut() else {
                return status(evt, "unlock a profile first", Level::Warn);
            };
            handle_unlocked(other, s, evt);
        }
    }
}

fn open_session(session: &mut Option<Session>, store: UnlockedStore, profile: Profile, evt: &Sender<Event>) {
    // Decrypt the Tor state from the vault into the working dir before any Tor use.
    #[cfg(feature = "tor")]
    crate::tor_ep::restore_state(&store);

    let view = ProfileView {
        name: profile.display_name.clone(),
        fingerprint: profile.fingerprint().unwrap_or_default(),
        bundle: profile.bundle().map(|b| b.encode()).unwrap_or_default(),
        kdf: "Argon2id · 64 MiB · t=3 · p=4".into(),
    };
    let s = Session {
        store,
        profile,
        group_cursor: HashMap::new(),
        group_seen: HashMap::new(),
        group_thread: HashMap::new(),
        inbox: Vec::new(),
        inbox_seen: HashSet::new(),
        use_tor: false,
    };
    let _ = evt.send(Event::Unlocked(view));
    push_state(&s, evt);
    *session = Some(s);
}

fn handle_unlocked(cmd: Command, s: &mut Session, evt: &Sender<Event>) {
    match cmd {
        Command::ChangePassphrase { new } => {
            let pass = Zeroizing::new(new.as_bytes().to_vec());
            match s.store.change_passphrase(&pass, &s.profile) {
                Ok(()) => status(evt, "passphrase changed", Level::Good),
                Err(e) => status(evt, format!("change failed: {e}"), Level::Bad),
            }
        }
        Command::AddContact { alias, bundle } => {
            let b = match KeyBundle::decode(bundle.trim()) {
                Ok(b) => b,
                Err(e) => return status(evt, format!("invalid bundle: {e}"), Level::Bad),
            };
            match s.profile.add_contact(&alias, &b) {
                Ok(()) => save_and(s, evt, format!("added '{alias}'"), Level::Good),
                Err(e) => status(evt, format!("{e}"), Level::Bad),
            }
        }
        Command::SetVerified { alias, verified } => {
            if s.profile.set_contact_verified(&alias, verified) {
                save_and(
                    s,
                    evt,
                    if verified {
                        format!("marked '{alias}' verified")
                    } else {
                        format!("unmarked '{alias}'")
                    },
                    Level::Good,
                );
            }
        }
        Command::RemoveContact { alias } => {
            if s.profile.remove_contact(&alias) {
                save_and(s, evt, format!("removed '{alias}'"), Level::Info);
            }
        }
        Command::CreateGroup { name } => {
            let g = Group::create(&name);
            match s.profile.add_group(g.to_stored()) {
                Ok(()) => save_and(s, evt, format!("created group '{name}'"), Level::Good),
                Err(e) => status(evt, format!("{e}"), Level::Bad),
            }
        }
        Command::JoinGroup { descriptor } => match Group::from_descriptor(descriptor.trim()) {
            Ok(g) => {
                let name = g.name.clone();
                match s.profile.add_group(g.to_stored()) {
                    Ok(()) => save_and(s, evt, format!("joined '{name}'"), Level::Good),
                    Err(e) => status(evt, format!("{e}"), Level::Bad),
                }
            }
            Err(e) => status(evt, format!("invalid descriptor: {e}"), Level::Bad),
        },
        Command::LeaveGroup { name } => {
            if s.profile.remove_group(&name) {
                s.group_thread.remove(&name);
                save_and(s, evt, format!("left '{name}'"), Level::Info);
            }
        }
        Command::GroupPost { group, relay, text } => group_post(s, evt, &group, &relay, &text),
        Command::GroupFetch { group, relay } => group_fetch(s, evt, &group, &relay),
        Command::MsgSend {
            alias,
            mailbox,
            text,
        } => msg_send(s, evt, &alias, &mailbox, &text),
        Command::MsgCollect { mailbox } => msg_collect(s, evt, &mailbox),
        Command::CallSendFile { relay, id, file } => {
            spawn_call(s, evt, move |ident, xw, tx| call_send_file(&relay, &id, ident, xw, &file, &tx))
        }
        Command::CallRecvFile { relay, id, out_dir } => {
            spawn_call(s, evt, move |ident, xw, tx| call_recv_file(&relay, &id, ident, xw, &out_dir, &tx))
        }
        Command::CallDial { relay, id, video, seconds } => {
            spawn_call(s, evt, move |ident, xw, tx| call_dial(&relay, &id, ident, xw, video, seconds, &tx))
        }
        Command::CallAnswer { relay, id, video } => {
            spawn_call(s, evt, move |ident, xw, tx| call_answer(&relay, &id, ident, xw, video, &tx))
        }
        _ => {}
    }
}

/// Run a call/transfer on its own thread (they can block for the call's
/// duration) so the engine stays responsive.
fn spawn_call<F>(s: &Session, evt: &Sender<Event>, f: F)
where
    F: FnOnce(Identity, XWingPrivate, Sender<Event>) + Send + 'static,
{
    let (ident, xw) = match (s.profile.identity(), s.profile.xwing()) {
        (Ok(i), Ok(x)) => (i, x),
        _ => return status(evt, "profile key error", Level::Bad),
    };
    let tx = evt.clone();
    std::thread::spawn(move || f(ident, xw, tx));
}

fn call_send_file(
    relay: &str,
    id: &str,
    ident: Identity,
    xw: XWingPrivate,
    file: &std::path::Path,
    tx: &Sender<Event>,
) {
    use unichat_core::session::initiator_handshake;
    use unichat_core::xfer::send_file;
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => return status(tx, format!("read failed: {e}"), Level::Bad),
    };
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    status(tx, format!("connecting to relay {relay}…"), Level::Info);
    let conn = match unichat_core::call::rendezvous(&TcpTransport, relay, id.as_bytes(), true) {
        Ok(c) => c,
        Err(e) => return status(tx, format!("relay error: {e}"), Level::Bad),
    };
    let mut ch = match initiator_handshake(conn, &ident, &xw) {
        Ok(c) => c,
        Err(e) => return status(tx, format!("handshake failed: {e}"), Level::Bad),
    };
    match send_file(&mut ch, &name, &data) {
        Ok(true) => status(tx, format!("sent '{name}' ({} B) E2E", data.len()), Level::Good),
        Ok(false) => status(tx, "peer declined", Level::Warn),
        Err(e) => status(tx, format!("send failed: {e}"), Level::Bad),
    }
}

fn call_recv_file(
    relay: &str,
    id: &str,
    ident: Identity,
    xw: XWingPrivate,
    out_dir: &std::path::Path,
    tx: &Sender<Event>,
) {
    use unichat_core::session::responder_handshake;
    use unichat_core::xfer::recv_file;
    status(tx, format!("waiting on relay {relay}…"), Level::Info);
    let conn = match unichat_core::call::rendezvous(&TcpTransport, relay, id.as_bytes(), false) {
        Ok(c) => c,
        Err(e) => return status(tx, format!("relay error: {e}"), Level::Bad),
    };
    let mut ch = match responder_handshake(conn, &ident, &xw) {
        Ok(c) => c,
        Err(e) => return status(tx, format!("handshake failed: {e}"), Level::Bad),
    };
    match recv_file(&mut ch, true) {
        Ok(Some((name, data))) => {
            std::fs::create_dir_all(out_dir).ok();
            let safe: String = name.rsplit(['/', '\\']).next().unwrap_or("file")
                .chars().filter(|c| !c.is_control() && !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|')).collect();
            let path = out_dir.join(if safe.is_empty() { "file".into() } else { safe });
            let _ = std::fs::write(&path, &data);
            status(tx, format!("received '{name}' ({} B) -> {}", data.len(), path.display()), Level::Good);
        }
        Ok(None) => status(tx, "no file received", Level::Info),
        Err(e) => status(tx, format!("receive failed: {e}"), Level::Bad),
    }
}

#[cfg(not(feature = "media"))]
fn synth(n: usize, i: u32) -> Vec<u8> {
    let mut v = vec![0u8; n];
    v[0..4].copy_from_slice(&i.to_le_bytes());
    v
}

/// Drive a live call over an already-handshaked stream. With the `media`
/// feature (default) this captures the real mic/camera, plays received audio,
/// and forwards decoded video frames to the UI; otherwise it falls back to the
/// synthetic media path. `max_secs` bounds the caller's side; `None` (callee)
/// runs until the peer hangs up.
fn run_call_media(
    stream: std::net::TcpStream,
    secret: [u8; 32],
    caller: bool,
    video: bool,
    max_secs: Option<u32>,
    tx: &Sender<Event>,
) {
    #[cfg(feature = "media")]
    {
        use std::sync::{Arc, Mutex};
        // run_call fans status out from several threads, so the callback must be
        // Sync — wrap the (Send-but-!Sync) event sender in a Mutex.
        let etx = Arc::new(Mutex::new(tx.clone()));
        let status_cb: Arc<dyn Fn(String) + Send + Sync> = {
            let etx = etx.clone();
            Arc::new(move |m: String| {
                if let Ok(g) = etx.lock() {
                    let _ = g.send(Event::Status(m, Level::Info));
                }
            })
        };
        // Forward decoded incoming video frames to the UI as events.
        let (vtx, vrx) = std::sync::mpsc::channel::<unichat_media::VideoFrame>();
        {
            let etx = tx.clone();
            std::thread::spawn(move || {
                while let Ok(f) = vrx.recv() {
                    let _ = etx.send(Event::VideoFrame {
                        width: f.width,
                        height: f.height,
                        rgba: f.rgba,
                    });
                }
            });
        }
        let handle = match unichat_media::run_call(stream, secret, caller, video, Some(vtx), status_cb) {
            Ok(h) => h,
            Err(e) => {
                status(tx, format!("media error: {e}"), Level::Bad);
                let _ = tx.send(Event::CallEnded);
                return;
            }
        };
        let start = std::time::Instant::now();
        loop {
            if handle.ended() {
                break;
            }
            if let Some(secs) = max_secs {
                if start.elapsed().as_secs() >= secs as u64 {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
        handle.hang_up();
        let _ = tx.send(Event::CallEnded);
    }
    #[cfg(not(feature = "media"))]
    {
        use unichat_core::call::{MediaKind, SecureMediaChannel};
        let mut media = match SecureMediaChannel::new(stream, &Zeroizing::new(secret), caller) {
            Ok(m) => m,
            Err(e) => {
                status(tx, format!("media init: {e}"), Level::Bad);
                let _ = tx.send(Event::CallEnded);
                return;
            }
        };
        status(tx, "call connected (E2E)", Level::Good);
        let frames = max_secs.unwrap_or(5).max(1) * 50;
        for i in 0..frames {
            if media.send(MediaKind::Audio, i, &synth(160, i)).is_err() {
                break;
            }
            if video {
                let _ = media.send(MediaKind::Video, i, &synth(1024, i));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        status(tx, "call ended", Level::Info);
        let _ = tx.send(Event::CallEnded);
    }
}

fn call_dial(
    relay: &str,
    id: &str,
    ident: Identity,
    xw: XWingPrivate,
    video: bool,
    seconds: u32,
    tx: &Sender<Event>,
) {
    use unichat_core::session::initiator_handshake;
    status(tx, format!("calling via {relay}…"), Level::Info);
    let conn = match unichat_core::call::rendezvous(&TcpTransport, relay, id.as_bytes(), true) {
        Ok(c) => c,
        Err(e) => return status(tx, format!("relay error: {e}"), Level::Bad),
    };
    let ch = match initiator_handshake(conn, &ident, &xw) {
        Ok(c) => c,
        Err(e) => return status(tx, format!("handshake failed: {e}"), Level::Bad),
    };
    let secret = ch.call_secret().clone();
    let caller = ch.is_initiator();
    let stream = ch.into_inner();
    // Caller drives the call for the requested duration (or until the peer drops).
    run_call_media(stream, *secret, caller, video, Some(seconds), tx);
}

fn call_answer(
    relay: &str,
    id: &str,
    ident: Identity,
    xw: XWingPrivate,
    video: bool,
    tx: &Sender<Event>,
) {
    use unichat_core::session::responder_handshake;
    status(tx, format!("waiting for call on {relay}…"), Level::Info);
    let conn = match unichat_core::call::rendezvous(&TcpTransport, relay, id.as_bytes(), false) {
        Ok(c) => c,
        Err(e) => return status(tx, format!("relay error: {e}"), Level::Bad),
    };
    let ch = match responder_handshake(conn, &ident, &xw) {
        Ok(c) => c,
        Err(e) => return status(tx, format!("handshake failed: {e}"), Level::Bad),
    };
    let secret = ch.call_secret().clone();
    let caller = ch.is_initiator();
    let stream = ch.into_inner();
    // Callee stays in the call until the peer hangs up.
    run_call_media(stream, *secret, caller, video, None, tx);
}

fn save_and(s: &Session, evt: &Sender<Event>, msg: String, level: Level) {
    if let Err(e) = s.store.save(&s.profile) {
        return status(evt, format!("save failed: {e}"), Level::Bad);
    }
    status(evt, msg, level);
    push_state(s, evt);
}

fn who_for(profile: &Profile, sender_id: &[u8; 32], my_id: &[u8; 32]) -> (String, bool) {
    if sender_id == my_id {
        return ("me".into(), false);
    }
    if let Some(c) = profile
        .contacts
        .iter()
        .find(|c| c.identity_pk().map(|k| &k == sender_id).unwrap_or(false))
    {
        (c.alias.clone(), false)
    } else {
        let fp: String = sender_id[..4].iter().map(|b| format!("{b:02x}")).collect();
        (format!("member#{fp}"), true)
    }
}

// --- network ops. `dial_with!` runs the body once with a concrete transport,
// selecting TCP or (Tor build) an onion endpoint per the profile toggle. ---
macro_rules! dial_with {
    ($s:expr, $evt:expr, $t:ident => $body:expr) => {{
        #[cfg(feature = "tor")]
        {
            if $s.use_tor {
                match crate::tor_ep::endpoint() {
                    Ok(ep) => {
                        let $t = &*ep;
                        $body
                    }
                    Err(e) => return status($evt, format!("Tor: {e}"), Level::Bad),
                }
            } else {
                let tcp = TcpTransport;
                let $t = &tcp;
                $body
            }
        }
        #[cfg(not(feature = "tor"))]
        {
            let tcp = TcpTransport;
            let $t = &tcp;
            $body
        }
    }};
}

fn group_post(s: &mut Session, evt: &Sender<Event>, group: &str, relay_addr: &str, text: &str) {
    let Some(sg) = s.profile.group(group) else {
        return status(evt, "not a member of that group", Level::Warn);
    };
    let g = match Group::from_stored(sg) {
        Ok(g) => g,
        Err(e) => return status(evt, format!("{e}"), Level::Bad),
    };
    let identity = match s.profile.identity() {
        Ok(i) => i,
        Err(e) => return status(evt, format!("{e}"), Level::Bad),
    };
    let blob = match group_seal(&g, &identity, text) {
        Ok(b) => b,
        Err(e) => return status(evt, format!("seal: {e}"), Level::Bad),
    };
    let gid = *g.group_id();
    let res = dial_with!(s, evt, t => relay::post(t, relay_addr, &gid, &blob));
    match res {
        Ok(_) => {
            status(evt, "posted", Level::Good);
            group_fetch(s, evt, group, relay_addr);
        }
        Err(e) => status(evt, format!("post failed: {e}"), Level::Bad),
    }
}

fn group_fetch(s: &mut Session, evt: &Sender<Event>, group: &str, relay_addr: &str) {
    let Some(sg) = s.profile.group(group) else {
        return status(evt, "not a member of that group", Level::Warn);
    };
    let g = match Group::from_stored(sg) {
        Ok(g) => g,
        Err(e) => return status(evt, format!("{e}"), Level::Bad),
    };
    let gid = *g.group_id();
    let since = *s.group_cursor.get(group).unwrap_or(&0);
    let res = dial_with!(s, evt, t => relay::fetch(t, relay_addr, &gid, since));
    let (blobs, cursor) = match res {
        Ok(v) => v,
        Err(e) => return status(evt, format!("fetch failed: {e}"), Level::Bad),
    };
    let my_id = s.profile.identity().map(|i| i.public_bytes()).unwrap_or([0u8; 32]);
    let seen = s.group_seen.entry(group.to_string()).or_default();
    let thread = s.group_thread.entry(group.to_string()).or_default();
    let mut added = 0;
    for blob in &blobs {
        if let Ok(m) = group_open(&g, blob) {
            if seen.insert(m.id) {
                // M1: dedup replays by authenticated message id
                let (who, unknown) = who_for(&s.profile, &m.sender_id, &my_id);
                thread.push(MessageView {
                    who,
                    body: m.body,
                    mine: m.sender_id == my_id,
                    unknown,
                    ts: m.ts,
                });
                added += 1;
            }
        }
    }
    thread.sort_by_key(|m| m.ts);
    s.group_cursor.insert(group.to_string(), cursor);
    let _ = evt.send(Event::GroupThread {
        group: group.to_string(),
        messages: thread.clone(),
    });
    if added > 0 {
        status(evt, format!("{added} new message(s)"), Level::Info);
    }
}

fn msg_send(s: &mut Session, evt: &Sender<Event>, alias: &str, mailbox_addr: &str, text: &str) {
    let Some(contact) = s.profile.contact(alias) else {
        return status(evt, "no such contact", Level::Warn);
    };
    let (rid, xpk) = match (contact.identity_pk(), contact.xwing_public()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return status(evt, "contact key corrupt", Level::Bad),
    };
    let identity = match s.profile.identity() {
        Ok(i) => i,
        Err(e) => return status(evt, format!("{e}"), Level::Bad),
    };
    let blob = match seal_message(&identity, &rid, &xpk, text.as_bytes()) {
        Ok(b) => b,
        Err(e) => return status(evt, format!("seal: {e}"), Level::Bad),
    };
    let res = dial_with!(s, evt, t => mailbox::deposit(t, mailbox_addr, &rid, &blob));
    match res {
        Ok(()) => status(evt, format!("sent to '{alias}'"), Level::Good),
        Err(e) => status(evt, format!("send failed: {e}"), Level::Bad),
    }
}

fn msg_collect(s: &mut Session, evt: &Sender<Event>, mailbox_addr: &str) {
    let identity = match s.profile.identity() {
        Ok(i) => i,
        Err(e) => return status(evt, format!("{e}"), Level::Bad),
    };
    let res = dial_with!(s, evt, t => mailbox::collect(t, mailbox_addr, &identity));
    let blobs = match res {
        Ok(v) => v,
        Err(e) => return status(evt, format!("collect failed: {e}"), Level::Bad),
    };
    let my_id = identity.public_bytes();
    let mut added = 0;
    for blob in &blobs {
        if let Ok(m) = open_message(&s.profile, blob) {
            if s.inbox_seen.insert(m.id) {
                let (who, unknown) = who_for(&s.profile, &m.sender_id, &my_id);
                s.inbox.push(MessageView {
                    who,
                    body: String::from_utf8_lossy(&m.plaintext).into_owned(),
                    mine: false,
                    unknown,
                    ts: 0,
                });
                added += 1;
            }
        }
    }
    let _ = evt.send(Event::Inbox(s.inbox.clone()));
    status(
        evt,
        format!("collected {added} new message(s)"),
        if added > 0 { Level::Good } else { Level::Info },
    );
}

fn spawn_mailbox(bind: &str, evt: &Sender<Event>) {
    match TcpListener::bind(bind) {
        Ok(listener) => {
            let addr = listener.address().unwrap_or_else(|_| bind.to_string());
            let store = mailbox::MailboxStore::new();
            thread::spawn(move || loop {
                match listener.accept() {
                    Ok(c) => {
                        let s = store.clone();
                        thread::spawn(move || {
                            let _ = s.handle_connection(c);
                        });
                    }
                    Err(_) => break,
                }
            });
            let _ = evt.send(Event::ServerUp {
                kind: "mailbox".into(),
                addr,
            });
        }
        Err(e) => status(evt, format!("mailbox bind failed: {e}"), Level::Bad),
    }
}

fn spawn_relay(bind: &str, evt: &Sender<Event>) {
    match TcpListener::bind(bind) {
        Ok(listener) => {
            let addr = listener.address().unwrap_or_else(|_| bind.to_string());
            let relay = relay::GroupRelay::new();
            thread::spawn(move || loop {
                match listener.accept() {
                    Ok(c) => {
                        let r = relay.clone();
                        thread::spawn(move || {
                            let _ = r.handle_connection(c);
                        });
                    }
                    Err(_) => break,
                }
            });
            let _ = evt.send(Event::ServerUp {
                kind: "relay".into(),
                addr,
            });
        }
        Err(e) => status(evt, format!("relay bind failed: {e}"), Level::Bad),
    }
}

// Silence unused-in-notor-build warnings for ContactState import.
#[allow(dead_code)]
fn _uses(_: ContactState) {}
