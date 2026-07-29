//! unichat-seal — standalone offline file encryption.
//!
//! PQSpread's feature (serverless, client-side post-quantum file exchange),
//! upgraded: hybrid X-Wing (ML-KEM-768 + X25519) instead of bare ML-KEM-512,
//! AES-256-GCM streaming records instead of one-shot, Argon2id-protected key
//! files, and the original filename travels encrypted inside the envelope.

use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use unichat_core::crypto::{envelope, keyfile, xwing::XWingPrivate};

#[derive(Parser)]
#[command(
    name = "unichat-seal",
    version,
    about = "Offline hybrid post-quantum file encryption (X-Wing: ML-KEM-768 + X25519, AES-256-GCM, Argon2id)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new keypair: <name>.key (secret) and <name>.pub (shareable).
    Keygen {
        /// Output base name (or path) for the key files.
        #[arg(long)]
        out: PathBuf,
        /// Store the secret seed unencrypted (NOT recommended).
        #[arg(long)]
        no_passphrase: bool,
        /// Overwrite existing key files.
        #[arg(long)]
        force: bool,
    },
    /// Encrypt a file to a recipient's public key.
    Encrypt {
        /// Recipient public key: a .pub file path or the literal key string.
        #[arg(long)]
        to: String,
        /// File to encrypt.
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
        /// Output path (default: <input>.usealed).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Overwrite the output if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Decrypt a .usealed file with your secret key.
    Decrypt {
        /// Your secret key file (.key).
        #[arg(long)]
        key: PathBuf,
        /// The .usealed file to decrypt.
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
        /// Directory to place the decrypted file in (default: current dir).
        /// The embedded original filename is used, after sanitization.
        #[arg(long, conflicts_with = "out")]
        out_dir: Option<PathBuf>,
        /// Exact output path (overrides the embedded filename).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Overwrite the output if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Print the public key belonging to a secret key file.
    Pubkey {
        /// Your secret key file (.key).
        #[arg(long)]
        key: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            out,
            no_passphrase,
            force,
        } => keygen(&out, no_passphrase, force),
        Command::Encrypt {
            to,
            input,
            out,
            force,
        } => encrypt(&to, &input, out.as_deref(), force),
        Command::Decrypt {
            key,
            input,
            out_dir,
            out,
            force,
        } => decrypt(&key, &input, out_dir.as_deref(), out.as_deref(), force),
        Command::Pubkey { key } => pubkey(&key),
    }
}

/// Passphrase source: UNICHAT_SEAL_PASSPHRASE env var (automation) or
/// interactive prompt.
fn read_passphrase(confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(p) = std::env::var("UNICHAT_SEAL_PASSPHRASE") {
        return Ok(Zeroizing::new(p.into_bytes()));
    }
    let first = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
    if confirm {
        let second = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")?);
        if *first != *second {
            bail!("passphrases do not match");
        }
    }
    if first.is_empty() {
        bail!("empty passphrase (use --no-passphrase to store the key unencrypted)");
    }
    Ok(Zeroizing::new(first.as_bytes().to_vec()))
}

fn refuse_existing(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!("{} already exists (use --force to overwrite)", path.display());
    }
    Ok(())
}

fn keygen(out: &Path, no_passphrase: bool, force: bool) -> Result<()> {
    let key_path = out.with_extension("key");
    let pub_path = out.with_extension("pub");
    refuse_existing(&key_path, force)?;
    refuse_existing(&pub_path, force)?;

    let key = XWingPrivate::generate().context("key generation failed")?;
    let passphrase = if no_passphrase {
        None
    } else {
        Some(read_passphrase(true)?)
    };
    let secret_bytes = keyfile::encode_secret(&key, passphrase.as_ref())?;
    fs::write(&key_path, &secret_bytes)
        .with_context(|| format!("writing {}", key_path.display()))?;
    fs::write(&pub_path, keyfile::encode_public(key.public_key_bytes()) + "\n")
        .with_context(|| format!("writing {}", pub_path.display()))?;

    println!("secret key: {}", key_path.display());
    println!("public key: {}", pub_path.display());
    println!("\nShare the PUBLIC key with peers who should encrypt files to you.");
    if no_passphrase {
        eprintln!("warning: secret key stored WITHOUT passphrase protection");
    }
    Ok(())
}

fn load_public(to: &str) -> Result<unichat_core::crypto::xwing::XWingPublic> {
    let text = if Path::new(to).exists() {
        fs::read_to_string(to).with_context(|| format!("reading {to}"))?
    } else {
        to.to_string()
    };
    let pk = keyfile::decode_public(&text).context(
        "invalid recipient key: pass a .pub file path or a unichat-xwing-pub-v1:... string",
    )?;
    Ok(unichat_core::crypto::xwing::XWingPublic::from_bytes(&pk)?)
}

fn load_secret(key_path: &Path) -> Result<XWingPrivate> {
    let data = fs::read(key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let passphrase = if keyfile::secret_needs_passphrase(&data)? {
        Some(read_passphrase(false)?)
    } else {
        None
    };
    Ok(keyfile::decode_secret(&data, passphrase.as_ref())?)
}

fn encrypt(to: &str, input: &Path, out: Option<&Path>, force: bool) -> Result<()> {
    let recipient = load_public(to)?;
    let meta_len = fs::metadata(input)
        .with_context(|| format!("reading {}", input.display()))?
        .len();
    let filename = input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let meta = envelope::Metadata {
        filename,
        mime: String::new(),
        size: meta_len,
    };

    let default_out = PathBuf::from(format!("{}.usealed", input.display()));
    let out_path = out.map(Path::to_path_buf).unwrap_or(default_out);
    refuse_existing(&out_path, force)?;

    let mut reader = BufReader::new(fs::File::open(input)?);
    let tmp_path = out_path.with_extension("usealed.part");
    let result = (|| -> Result<()> {
        let mut writer = BufWriter::new(fs::File::create(&tmp_path)?);
        envelope::seal(&recipient, &meta, &mut reader, &mut writer)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            if force && out_path.exists() {
                fs::remove_file(&out_path)?;
            }
            fs::rename(&tmp_path, &out_path)?;
            println!("sealed: {}", out_path.display());
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// The embedded filename is attacker-influenced data: reduce it to a safe,
/// plain basename before using it on the local filesystem.
fn sanitize_filename(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        .take(200)
        .collect::<String>();
    let trimmed = base.trim().trim_end_matches('.').to_string();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return "decrypted.bin".to_string();
    }
    let stem = trimmed
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem.as_str()) {
        format!("_{trimmed}")
    } else {
        trimmed
    }
}

fn decrypt(
    key_path: &Path,
    input: &Path,
    out_dir: Option<&Path>,
    out: Option<&Path>,
    force: bool,
) -> Result<()> {
    let key = load_secret(key_path)?;
    let reader = BufReader::new(
        fs::File::open(input).with_context(|| format!("reading {}", input.display()))?,
    );
    let opener = envelope::Opener::new(&key, reader)
        .context("cannot open envelope (wrong key, corrupted, or not a .usealed file)")?;

    let out_path = match out {
        Some(p) => p.to_path_buf(),
        None => {
            let dir = out_dir.unwrap_or(Path::new("."));
            dir.join(sanitize_filename(&opener.metadata().filename))
        }
    };
    refuse_existing(&out_path, force)?;
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }

    let tmp_path = out_path.with_extension("part");
    let result = (|| -> Result<u64> {
        let mut writer = BufWriter::new(fs::File::create(&tmp_path)?);
        let n = opener.copy_to(&mut writer)?;
        Ok(n)
    })();
    match result {
        Ok(n) => {
            if force && out_path.exists() {
                fs::remove_file(&out_path)?;
            }
            fs::rename(&tmp_path, &out_path)?;
            println!("decrypted {n} bytes -> {}", out_path.display());
            Ok(())
        }
        Err(e) => {
            // Fail closed: never leave partial plaintext behind.
            let _ = fs::remove_file(&tmp_path);
            Err(e).context("decryption FAILED — file discarded (tampering or wrong key)")
        }
    }
}

fn pubkey(key_path: &Path) -> Result<()> {
    let key = load_secret(key_path)?;
    println!("{}", keyfile::encode_public(key.public_key_bytes()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sanitize_filename;

    #[test]
    fn sanitize_strips_paths_and_reserved_names() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("..\\..\\boot.ini"), "boot.ini");
        assert_eq!(sanitize_filename(""), "decrypted.bin");
        assert_eq!(sanitize_filename(".."), "decrypted.bin");
        assert_eq!(sanitize_filename("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_filename("normal-file.tar.gz"), "normal-file.tar.gz");
        assert_eq!(sanitize_filename("trailing..."), "trailing");
    }
}
