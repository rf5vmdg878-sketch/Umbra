//! `umbra-manifest` — release tooling to arm Umbra's tamper-evidence.
//!
//!   umbra-manifest genkey <privkey-out>
//!       Generate an Ed25519 release keypair. Writes the 32-byte private seed to
//!       <privkey-out> (KEEP IT SECRET / OFFLINE) and prints the public key,
//!       including a ready-to-paste `RELEASE_PUBKEY` array for integrity.rs.
//!
//!   umbra-manifest sign <privkey> <dir> [file ...]
//!       Hash each file (relative to <dir>; default = every regular file in
//!       <dir> except the manifest) and write a signed <dir>/umbra.manifest.
//!
//!   umbra-manifest verify <pubkey-hex> <dir>
//!       Verify the manifest signature and that every listed file matches.

use std::path::{Path, PathBuf};
use std::process::exit;

use ed25519_dalek::{Signer, SigningKey};
use unichat_core::integrity::{manifest_body, parse_verified, sha256_file, MANIFEST_NAME};
use zeroize::Zeroizing;

fn to_hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn die(msg: &str) -> ! {
    eprintln!("umbra-manifest: {msg}");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("genkey") => genkey(args.get(2).map(PathBuf::from)),
        Some("sign") => sign(&args[2..]),
        Some("verify") => verify(&args[2..]),
        _ => {
            eprintln!(
                "usage:\n  umbra-manifest genkey <privkey-out>\n  \
                 umbra-manifest sign <privkey> <dir> [file ...]\n  \
                 umbra-manifest verify <pubkey-hex> <dir>"
            );
            exit(2);
        }
    }
}

fn genkey(out: Option<PathBuf>) {
    let out = out.unwrap_or_else(|| die("genkey needs an output path for the private seed"));
    let mut seed = Zeroizing::new([0u8; 32]);
    unichat_core::crypto::random_bytes(seed.as_mut());
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();

    if let Err(e) = std::fs::write(&out, seed.as_ref()) {
        die(&format!("writing private seed: {e}"));
    }
    println!("private seed written to {} (keep it secret & offline)", out.display());
    println!("public key (hex): {}", to_hex(&pk));
    println!("\nPaste into unichat-common/core/src/integrity.rs:");
    print!("pub const RELEASE_PUBKEY: [u8; 32] = [");
    for (i, b) in pk.iter().enumerate() {
        if i % 12 == 0 {
            print!("\n    ");
        }
        print!("0x{b:02x}, ");
    }
    println!("\n];");
}

fn collect_files(dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                let name = e.file_name().to_string_lossy().into_owned();
                if name != MANIFEST_NAME {
                    names.push(name);
                }
            }
        }
    }
    names.sort();
    names
}

fn sign(rest: &[String]) {
    if rest.len() < 2 {
        die("sign needs <privkey> <dir> [file ...]");
    }
    let seed_bytes = std::fs::read(&rest[0]).unwrap_or_else(|e| die(&format!("reading privkey: {e}")));
    if seed_bytes.len() != 32 {
        die("private seed must be exactly 32 bytes");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&seed_bytes);
    let sk = SigningKey::from_bytes(&seed);

    let dir = PathBuf::from(&rest[1]);
    let files: Vec<String> = if rest.len() > 2 {
        rest[2..].to_vec()
    } else {
        collect_files(&dir)
    };
    if files.is_empty() {
        die("no files to include in the manifest");
    }

    let mut entries = Vec::new();
    for rel in &files {
        let hash = sha256_file(&dir.join(rel)).unwrap_or_else(|e| die(&format!("hashing {rel}: {e}")));
        entries.push((rel.clone(), hash));
    }
    let body = manifest_body(&entries);
    let sig = sk.sign(&body);
    let mut out = body;
    out.extend_from_slice(&sig.to_bytes());

    let path = dir.join(MANIFEST_NAME);
    std::fs::write(&path, &out).unwrap_or_else(|e| die(&format!("writing manifest: {e}")));
    println!("signed {} files -> {}", entries.len(), path.display());
    for (rel, _) in &entries {
        println!("  {rel}");
    }
}

fn verify(rest: &[String]) {
    if rest.len() < 2 {
        die("verify needs <pubkey-hex> <dir>");
    }
    let pk_vec = from_hex(&rest[0]).unwrap_or_else(|| die("pubkey must be 64 hex chars"));
    let pubkey: [u8; 32] = pk_vec.as_slice().try_into().unwrap_or_else(|_| die("pubkey must be 32 bytes"));
    let dir = PathBuf::from(&rest[1]);

    let bytes = std::fs::read(dir.join(MANIFEST_NAME))
        .unwrap_or_else(|e| die(&format!("reading manifest: {e}")));
    let entries = parse_verified(&bytes, &pubkey).unwrap_or_else(|e| die(&format!("signature: {e}")));

    let mut ok = true;
    for (rel, want) in &entries {
        match sha256_file(&dir.join(rel)) {
            Ok(got) if &got == want => println!("  ok    {rel}"),
            Ok(_) => {
                println!("  BAD   {rel} (hash mismatch)");
                ok = false;
            }
            Err(e) => {
                println!("  ERR   {rel} ({e})");
                ok = false;
            }
        }
    }
    if ok {
        println!("manifest OK — signature valid, {} files match", entries.len());
    } else {
        die("manifest verification FAILED");
    }
}
