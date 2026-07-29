//! unichat — client CLI (Tor build).
//!
//! Phase 2: encrypted profile management and contacts.
//! Phase 3: `chat` — 1:1 encrypted sessions over direct TCP, or over a Tor v3
//! onion service with `--tor` (requires building with `--features tor`).

mod call_cmd;
mod chat;
mod groups_cmd;
mod share_cmd;
mod sync_cmd;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use unichat_core::identity::{KeyBundle, Profile};
use unichat_core::storage::UnlockedStore;

#[derive(Parser)]
#[command(name = "unichat", version, about = "Unified secure communications suite")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Profile management.
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Contact management.
    Contact {
        #[command(subcommand)]
        cmd: ContactCmd,
    },
    /// 1:1 encrypted chat over the transport (TCP, or Tor with --tor).
    Chat {
        #[command(subcommand)]
        cmd: ChatCmd,
    },
    /// Run an untrusted store-and-forward mailbox node.
    Mailbox {
        #[command(subcommand)]
        cmd: MailboxCmd,
    },
    /// Offline messaging via a mailbox (store-and-forward).
    Msg {
        #[command(subcommand)]
        cmd: MsgCmd,
    },
    /// Untrusted-relay group messaging.
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
    /// Run an untrusted group relay node.
    Relay {
        #[command(subcommand)]
        cmd: RelayCmd,
    },
    /// Ephemeral file sharing (one-shot shares + receive dropbox).
    Share {
        #[command(subcommand)]
        cmd: ShareCmd,
    },
    /// E2E file transfer + voice/video calls routed through a relay.
    Call {
        #[command(subcommand)]
        cmd: CallCmd,
    },
}

#[derive(Subcommand)]
enum CallCmd {
    /// Send a file E2E to a peer through the relay.
    SendFile {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        relay: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Receive a file E2E from a peer through the relay.
    RecvFile {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        relay: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Place a call (streams synthetic voice/video through the relay).
    Dial {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        relay: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        video: bool,
        #[arg(long, default_value_t = 5)]
        seconds: u32,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Answer a call (receives + decrypts the media stream).
    Answer {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        relay: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ShareCmd {
    /// Host a file for download, auto-stopping after N downloads.
    Send {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value_t = 1)]
        downloads: usize,
        #[arg(long, default_value = "127.0.0.1:9920")]
        bind: String,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Download a shared file with its descriptor.
    Download {
        /// Host address (host:port, or <onion>.onion:9920 with --tor).
        #[arg(long)]
        from: String,
        #[arg(long)]
        descriptor: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Run an anonymous receive dropbox; decrypt uploads into a directory.
    Receive {
        #[arg(long, default_value = "127.0.0.1:9921")]
        bind: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "dropbox")]
        label: String,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Upload a file to a receive dropbox with its descriptor.
    Upload {
        /// Dropbox address (host:port, or <onion>.onion:9920 with --tor).
        #[arg(long)]
        to: String,
        #[arg(long)]
        descriptor: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum RelayCmd {
    /// Serve a group relay until interrupted.
    Serve {
        #[arg(long, default_value = "127.0.0.1:9910")]
        bind: String,
        /// Publish the relay as a Tor onion service instead of TCP.
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Create a new group and print its invite descriptor.
    Create {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// Join a group from an invite descriptor.
    Join {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        descriptor: String,
    },
    /// List joined groups.
    List {
        #[arg(long)]
        store: PathBuf,
    },
    /// Leave a group.
    Leave {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// Post a message to a group via a relay.
    Post {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        name: String,
        /// Relay address (host:port, or <onion>.onion:9910 with --tor).
        #[arg(long)]
        via: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Fetch and decrypt group messages from a relay.
    Fetch {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        via: String,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum MailboxCmd {
    /// Serve a mailbox until interrupted.
    Serve {
        /// Address to bind for TCP (ignored with --tor).
        #[arg(long, default_value = "127.0.0.1:9900")]
        bind: String,
        /// Publish the mailbox as a Tor onion service instead of TCP.
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum MsgCmd {
    /// Seal a message to a contact and deposit it at a mailbox.
    Send {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        to: String,
        /// Mailbox address (host:port, or <onion>.onion:9900 with --tor).
        #[arg(long)]
        via: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Collect and decrypt messages addressed to us from a mailbox.
    Collect {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        via: String,
        #[arg(long)]
        tor: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ChatCmd {
    /// Listen for one incoming session and print received messages.
    Serve {
        #[arg(long)]
        store: PathBuf,
        /// Address to bind for TCP, e.g. 127.0.0.1:9878 (ignored with --tor).
        #[arg(long, default_value = "127.0.0.1:9878")]
        bind: String,
        /// Auto-approve an unknown peer's contact request (knock).
        #[arg(long)]
        accept_unknown: bool,
        /// Publish a Tor v3 onion service instead of binding TCP.
        #[arg(long)]
        tor: bool,
        /// Directory for arti's persistent Tor state (default: <store>.tor-state).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Connect to a peer and send messages.
    Send {
        #[arg(long)]
        store: PathBuf,
        /// Peer address: host:port for TCP, or <onion>.onion:port with --tor.
        #[arg(long)]
        to: String,
        /// Send a contact request (knock) first, with this nickname.
        #[arg(long)]
        knock: Option<String>,
        /// Message(s) to send (repeatable).
        #[arg(long = "message")]
        messages: Vec<String>,
        /// Connect over Tor (peer address must be a .onion).
        #[arg(long)]
        tor: bool,
        /// Directory for arti's persistent Tor state (default: <store>.tor-state).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Create a new profile store.
    Create {
        /// Path for the new profile store file.
        #[arg(long)]
        store: PathBuf,
        /// Display name for this profile.
        #[arg(long)]
        name: String,
    },
    /// Show profile summary (name, fingerprint, contact count).
    Info {
        #[arg(long)]
        store: PathBuf,
    },
    /// Print the shareable signed key bundle.
    Bundle {
        #[arg(long)]
        store: PathBuf,
    },
    /// Change the store passphrase (data is re-wrapped, not re-encrypted).
    ChangePassphrase {
        #[arg(long)]
        store: PathBuf,
    },
}

#[derive(Subcommand)]
enum ContactCmd {
    /// Add a contact from their signed key bundle.
    Add {
        #[arg(long)]
        store: PathBuf,
        /// Local alias for the contact.
        #[arg(long)]
        alias: String,
        /// The bundle: a `unichat-bundle-v1:...` string or a path to a file
        /// containing one.
        #[arg(long)]
        bundle: String,
    },
    /// List contacts.
    List {
        #[arg(long)]
        store: PathBuf,
    },
    /// Remove a contact by alias.
    Remove {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        alias: String,
    },
}

fn main() -> Result<()> {
    unichat_core::integrity::enforce(); // refuse to run a tampered build
    match Cli::parse().command {
        Command::Profile { cmd } => match cmd {
            ProfileCmd::Create { store, name } => create(&store, &name),
            ProfileCmd::Info { store } => info(&store),
            ProfileCmd::Bundle { store } => bundle(&store),
            ProfileCmd::ChangePassphrase { store } => change_passphrase(&store),
        },
        Command::Contact { cmd } => match cmd {
            ContactCmd::Add {
                store,
                alias,
                bundle,
            } => contact_add(&store, &alias, &bundle),
            ContactCmd::List { store } => contact_list(&store),
            ContactCmd::Remove { store, alias } => contact_remove(&store, &alias),
        },
        Command::Chat { cmd } => match cmd {
            ChatCmd::Serve {
                store,
                bind,
                accept_unknown,
                tor,
                state_dir,
            } => chat::serve(&store, &bind, accept_unknown, tor, state_dir.as_deref()),
            ChatCmd::Send {
                store,
                to,
                knock,
                messages,
                tor,
                state_dir,
            } => chat::send(&store, &to, knock.as_deref(), &messages, tor, state_dir.as_deref()),
        },
        Command::Mailbox { cmd } => match cmd {
            MailboxCmd::Serve {
                bind,
                tor,
                state_dir,
            } => sync_cmd::mailbox_serve(&bind, tor, state_dir.as_deref()),
        },
        Command::Msg { cmd } => match cmd {
            MsgCmd::Send {
                store,
                to,
                via,
                message,
                tor,
                state_dir,
            } => sync_cmd::msg_send(&store, &to, &via, &message, tor, state_dir.as_deref()),
            MsgCmd::Collect {
                store,
                via,
                tor,
                state_dir,
            } => sync_cmd::msg_collect(&store, &via, tor, state_dir.as_deref()),
        },
        Command::Relay { cmd } => match cmd {
            RelayCmd::Serve {
                bind,
                tor,
                state_dir,
            } => groups_cmd::relay_serve(&bind, tor, state_dir.as_deref()),
        },
        Command::Call { cmd } => match cmd {
            CallCmd::SendFile { store, relay, id, file, tor, state_dir } => {
                call_cmd::send_file_cmd(&store, &relay, &id, &file, tor, state_dir.as_deref())
            }
            CallCmd::RecvFile { store, relay, id, out, tor, state_dir } => {
                call_cmd::recv_file_cmd(&store, &relay, &id, &out, tor, state_dir.as_deref())
            }
            CallCmd::Dial { store, relay, id, video, seconds, tor, state_dir } => {
                call_cmd::dial(&store, &relay, &id, video, seconds, tor, state_dir.as_deref())
            }
            CallCmd::Answer { store, relay, id, tor, state_dir } => {
                call_cmd::answer(&store, &relay, &id, tor, state_dir.as_deref())
            }
        },
        Command::Share { cmd } => match cmd {
            ShareCmd::Send {
                file,
                downloads,
                bind,
                tor,
                state_dir,
            } => share_cmd::send(&file, downloads, &bind, tor, state_dir.as_deref()),
            ShareCmd::Download {
                from,
                descriptor,
                out,
                tor,
                state_dir,
            } => share_cmd::download_cmd(&from, &descriptor, &out, tor, state_dir.as_deref()),
            ShareCmd::Receive {
                bind,
                out,
                label,
                tor,
                state_dir,
            } => share_cmd::receive(&bind, &out, &label, tor, state_dir.as_deref()),
            ShareCmd::Upload {
                to,
                descriptor,
                file,
                tor,
                state_dir,
            } => share_cmd::upload_cmd(&to, &descriptor, &file, tor, state_dir.as_deref()),
        },
        Command::Group { cmd } => match cmd {
            GroupCmd::Create { store, name } => groups_cmd::create(&store, &name),
            GroupCmd::Join { store, descriptor } => groups_cmd::join(&store, &descriptor),
            GroupCmd::List { store } => groups_cmd::list(&store),
            GroupCmd::Leave { store, name } => groups_cmd::leave(&store, &name),
            GroupCmd::Post {
                store,
                name,
                via,
                message,
                tor,
                state_dir,
            } => groups_cmd::post_msg(&store, &name, &via, &message, tor, state_dir.as_deref()),
            GroupCmd::Fetch {
                store,
                name,
                via,
                tor,
                state_dir,
            } => groups_cmd::fetch_msgs(&store, &name, &via, tor, state_dir.as_deref()),
        },
    }
}

/// Passphrase source: UNICHAT_PASSPHRASE env var (automation) or prompt.
fn read_passphrase(prompt: &str, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(p) = std::env::var("UNICHAT_PASSPHRASE") {
        return Ok(Zeroizing::new(p.into_bytes()));
    }
    let first = Zeroizing::new(rpassword::prompt_password(format!("{prompt}: "))?);
    if confirm {
        let second = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")?);
        if *first != *second {
            bail!("passphrases do not match");
        }
    }
    if first.is_empty() {
        bail!("empty passphrase not allowed for profile stores");
    }
    Ok(Zeroizing::new(first.as_bytes().to_vec()))
}

fn open_store(store: &Path) -> Result<(UnlockedStore, Profile)> {
    let pass = read_passphrase("Profile passphrase", false)?;
    Ok(UnlockedStore::open(store, &pass).context("failed to unlock profile store")?)
}

fn create(store: &Path, name: &str) -> Result<()> {
    let pass = read_passphrase("New profile passphrase", true)?;
    let profile = Profile::create(name)?;
    UnlockedStore::create(store, &pass, &profile)
        .context("failed to create profile store")?;
    println!("profile store: {}", store.display());
    println!("display name : {}", profile.display_name);
    println!("fingerprint  : {}", profile.fingerprint()?);
    println!("\nShare your bundle with `unichat profile bundle --store {}`", store.display());
    Ok(())
}

fn info(store: &Path) -> Result<()> {
    let (_s, profile) = open_store(store)?;
    println!("display name : {}", profile.display_name);
    println!("fingerprint  : {}", profile.fingerprint()?);
    println!("contacts     : {}", profile.contacts.len());
    Ok(())
}

fn bundle(store: &Path) -> Result<()> {
    let (_s, profile) = open_store(store)?;
    println!("{}", profile.bundle()?.encode());
    Ok(())
}

fn change_passphrase(store: &Path) -> Result<()> {
    let (mut s, profile) = open_store(store)?;
    let new = if let Ok(p) = std::env::var("UNICHAT_NEW_PASSPHRASE") {
        Zeroizing::new(p.into_bytes())
    } else {
        let first = Zeroizing::new(rpassword::prompt_password("New passphrase: ")?);
        let second = Zeroizing::new(rpassword::prompt_password("Confirm new passphrase: ")?);
        if *first != *second {
            bail!("passphrases do not match");
        }
        if first.is_empty() {
            bail!("empty passphrase not allowed");
        }
        Zeroizing::new(first.as_bytes().to_vec())
    };
    s.change_passphrase(&new, &profile)?;
    println!("passphrase changed");
    Ok(())
}

fn contact_add(store: &Path, alias: &str, bundle_arg: &str) -> Result<()> {
    let text = if Path::new(bundle_arg).exists() {
        std::fs::read_to_string(bundle_arg)?
    } else {
        bundle_arg.to_string()
    };
    let bundle = KeyBundle::decode(&text)
        .context("invalid bundle (signature verification failed or malformed)")?;
    let (s, mut profile) = open_store(store)?;
    profile.add_contact(alias, &bundle)?;
    s.save(&profile)?;
    println!("added contact '{alias}' ({})", bundle.fingerprint());
    Ok(())
}

fn contact_list(store: &Path) -> Result<()> {
    let (_s, profile) = open_store(store)?;
    if profile.contacts.is_empty() {
        println!("(no contacts)");
        return Ok(());
    }
    for c in &profile.contacts {
        println!(
            "{:<20} {:?}  {}",
            c.alias,
            c.state,
            c.fingerprint().unwrap_or_else(|_| "<corrupt>".into())
        );
    }
    Ok(())
}

fn contact_remove(store: &Path, alias: &str) -> Result<()> {
    let (s, mut profile) = open_store(store)?;
    if !profile.remove_contact(alias) {
        bail!("no contact with alias '{alias}'");
    }
    s.save(&profile)?;
    println!("removed '{alias}'");
    Ok(())
}
