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
use unichat_core::identity::{ContactState, KeyBundle, Profile};
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
    SetUseTor(bool),
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
        other => {
            let Some(s) = session.as_mut() else {
                return status(evt, "unlock a profile first", Level::Warn);
            };
            handle_unlocked(other, s, evt);
        }
    }
}

fn open_session(session: &mut Option<Session>, store: UnlockedStore, profile: Profile, evt: &Sender<Event>) {
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
        _ => {}
    }
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
