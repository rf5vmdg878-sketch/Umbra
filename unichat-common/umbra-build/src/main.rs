//! `umbra-build` — one command to build and package Umbra on Windows or Linux.
//!
//!   umbra-build [app|relay|all] [flags]
//!
//! Defaults to the **non-Tor** app. `--torify` builds the **Tor-hardened**
//! variant: for the app that's the onion-transport fork; for the relay it also
//! writes a private-mode config + a torrc onion template (safe defaults, ready
//! to run). It fetches SymCrypt for the platform, runs cargo with the right
//! features/target, optionally signs the integrity manifest, and can emit a
//! portable archive (.zip on Windows, .tar.gz on Linux).
//!
//! std-only by design: the bootstrap scripts build this before SymCrypt exists,
//! so it shells out to `cargo`, `curl`, and `tar` rather than linking anything.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const SYMCRYPT_VERSION: &str = "103.11.0";
// Default Linux SymCrypt release asset (override with --symcrypt-url). The exact
// asset name can drift between releases; if the download 404s, pass the correct
// URL from https://github.com/microsoft/SymCrypt/releases.
const SYMCRYPT_LINUX_URL: &str = "https://github.com/microsoft/SymCrypt/releases/download/v103.11.0/symcrypt-linux-generic-amd64-release-103.11.0-53be637.tar.gz";

struct Opts {
    target: String, // app | relay | all
    torify: bool,
    release: bool,
    media: bool,
    sign_key: Option<PathBuf>,
    package: bool,
    out: Option<PathBuf>,
    relay_path: Option<PathBuf>,
    symcrypt_url: String,
    skip_symcrypt: bool,
}

fn is_windows() -> bool {
    cfg!(windows)
}

fn fail(msg: &str) -> ! {
    eprintln!("umbra-build: {msg}");
    std::process::exit(1);
}

fn help() -> ! {
    println!(
        "umbra-build [app|relay|all] [flags]\n\n\
         Targets:\n  app (default)   build the desktop app + CLI\n  relay           build umbra-relay\n  all             build both\n\n\
         Flags:\n  --torify              Tor-hardened variant (onion app fork / private-mode relay)\n  \
         --debug               debug build (default: release)\n  \
         --no-media            app without real mic/camera capture\n  \
         --sign <keyfile>      Ed25519-sign the integrity manifest after building\n  \
         --package             emit a portable archive (.zip / .tar.gz)\n  \
         --out <dir>           archive output dir (default: <repo>/dist)\n  \
         --relay-path <dir>    location of the umbra-relay repo (default: <repo>/../umbra-relay)\n  \
         --symcrypt-url <url>  override the Linux SymCrypt download URL\n  \
         --skip-symcrypt       assume SymCrypt is already present\n  \
         -h, --help            this message"
    );
    std::process::exit(0);
}

fn parse_args() -> Opts {
    let mut o = Opts {
        target: "app".into(),
        torify: false,
        release: true,
        media: true,
        sign_key: None,
        package: false,
        out: None,
        relay_path: None,
        symcrypt_url: SYMCRYPT_LINUX_URL.into(),
        skip_symcrypt: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "app" | "relay" | "all" => o.target = a,
            // accept both --torify and -torify
            "--torify" | "-torify" => o.torify = true,
            "--debug" => o.release = false,
            "--no-media" => o.media = false,
            "--package" => o.package = true,
            "--skip-symcrypt" => o.skip_symcrypt = true,
            "--sign" => o.sign_key = Some(PathBuf::from(args.next().unwrap_or_else(|| fail("--sign needs a keyfile")))),
            "--out" => o.out = Some(PathBuf::from(args.next().unwrap_or_else(|| fail("--out needs a dir")))),
            "--relay-path" => o.relay_path = Some(PathBuf::from(args.next().unwrap_or_else(|| fail("--relay-path needs a dir")))),
            "--symcrypt-url" => o.symcrypt_url = args.next().unwrap_or_else(|| fail("--symcrypt-url needs a url")),
            "-h" | "--help" => help(),
            other => fail(&format!("unknown argument: {other}")),
        }
    }
    o
}

/// Walk up from CWD to the repo root (the dir holding unichat-common + the forks).
fn repo_root() -> PathBuf {
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        if dir.join("unichat-common").is_dir() && dir.join("unichat-notor").is_dir() {
            return dir;
        }
        if !dir.pop() {
            fail("could not locate the repo root (need unichat-common + unichat-notor)");
        }
    }
}

fn run(program: &str, args: &[&str], cwd: &Path, env: &BTreeMap<String, String>) {
    print!("→ {program}");
    for a in args {
        print!(" {a}");
    }
    println!("   (in {})", cwd.display());
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(cwd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    match cmd.status() {
        Ok(s) if s.success() => {}
        Ok(s) => fail(&format!("{program} exited with {s}")),
        Err(e) => fail(&format!("failed to run {program}: {e} (is it installed / on PATH?)")),
    }
}

/// Ensure SymCrypt is available; returns SYMCRYPT_LIB_PATH to set for cargo
/// (None on Windows, where the vendored path in .cargo/config.toml is used).
fn ensure_symcrypt(root: &Path, o: &Opts) -> Option<String> {
    let vendor = root.join("unichat-common").join("vendor").join("symcrypt");
    if is_windows() {
        // Windows ships the vendored DLL + import lib; .cargo/config points at it.
        if !o.skip_symcrypt && !vendor.join("dll").join("symcrypt.dll").exists() {
            eprintln!("warning: {}\\dll\\symcrypt.dll not found; Windows build may fail to link.", vendor.display());
        }
        return None;
    }
    // Linux: fetch libsymcrypt.so into vendor/symcrypt/linux and point cargo there.
    let lin = vendor.join("linux");
    let have = lin.join(format!("libsymcrypt.so.{}", SYMCRYPT_VERSION.split('.').next().unwrap_or("103"))).exists()
        || lin.join("libsymcrypt.so").exists();
    if o.skip_symcrypt || have {
        return Some(lin.to_string_lossy().into_owned());
    }
    std::fs::create_dir_all(&lin).ok();
    let tgz = lin.join("symcrypt-linux.tar.gz");
    println!("Fetching SymCrypt {SYMCRYPT_VERSION} for Linux …");
    run("curl", &["-L", "--fail", "-o", &tgz.to_string_lossy(), &o.symcrypt_url], root, &BTreeMap::new());
    // Extract; the archive lays libsymcrypt.so* somewhere under lib/. Flatten it.
    run("tar", &["xzf", &tgz.to_string_lossy(), "-C", &lin.to_string_lossy()], root, &BTreeMap::new());
    // Try to surface any libsymcrypt.so* into the linux/ root for a stable path.
    flatten_so(&lin);
    if !(lin.join("libsymcrypt.so").exists()
        || std::fs::read_dir(&lin).map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().starts_with("libsymcrypt.so"))).unwrap_or(false))
    {
        fail(&format!(
            "SymCrypt download did not yield libsymcrypt.so under {}.\n  \
             Check the release asset and pass --symcrypt-url <correct-url>.",
            lin.display()
        ));
    }
    Some(lin.to_string_lossy().into_owned())
}

/// Recursively move any libsymcrypt.so* found under `dir` up into `dir` itself.
fn flatten_so(dir: &Path) {
    fn walk(base: &Path, dir: &Path) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(base, &p);
                } else if e.file_name().to_string_lossy().starts_with("libsymcrypt.so") && p.parent() != Some(base) {
                    let _ = std::fs::rename(&p, base.join(e.file_name()));
                }
            }
        }
    }
    walk(dir, dir);
}

/// Build env: set SYMCRYPT_LIB_PATH (Linux) and rpath so the binary finds the
/// co-located libsymcrypt.so at runtime.
fn build_env(symcrypt: &Option<String>) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    if let Some(path) = symcrypt {
        env.insert("SYMCRYPT_LIB_PATH".into(), path.clone());
        // Find the .so next to the executable at runtime.
        env.insert("RUSTFLAGS".into(), "-C link-arg=-Wl,-rpath,$ORIGIN".into());
    }
    env
}

fn cargo_profile_dir(release: bool) -> &'static str {
    if release {
        "release"
    } else {
        "debug"
    }
}

fn build_app(root: &Path, o: &Opts, env: &BTreeMap<String, String>) -> PathBuf {
    let fork = if o.torify { "unichat-tor" } else { "unichat-notor" };
    let dir = root.join(fork);
    let mut args = vec!["build"];
    if o.release {
        args.push("--release");
    }
    if !o.media {
        args.push("--no-default-features");
    }
    if o.torify {
        args.push("--features");
        args.push("tor");
    }
    run("cargo", &args, &dir, env);
    dir.join("target").join(cargo_profile_dir(o.release))
}

fn build_relay(relay: &Path, o: &Opts, env: &BTreeMap<String, String>) -> PathBuf {
    if !relay.join("Cargo.toml").exists() {
        fail(&format!("umbra-relay not found at {} (pass --relay-path)", relay.display()));
    }
    let mut args = vec!["build"];
    if o.release {
        args.push("--release");
    }
    run("cargo", &args, relay, env);
    if o.torify {
        write_relay_tor_setup(relay);
    }
    relay.join("target").join(cargo_profile_dir(o.release))
}

/// Auto-setup safe Tor defaults for the relay: a private-mode config + a torrc
/// onion template so the operator only has to point Tor at it.
fn write_relay_tor_setup(relay: &Path) {
    let cfg = "# Generated by umbra-build --torify: loopback-only, reachable only\n\
               # via the Tor onion service defined in torrc.onion.sample.\n\
               group_bind = \"127.0.0.1:9910\"\n\
               mailbox_bind = \"127.0.0.1:9900\"\n\
               call_bind = \"127.0.0.1:9930\"\n\
               allow_ips = []\n\
               max_connections = 512\n\
               idle_timeout_secs = 90\n\
               spool_path = \"umbra-relay.spool\"\n\
               snapshot_interval_secs = 30\n\
               private_mode = true\n";
    let torrc = "# torrc snippet — expose the loopback relay as a Tor onion service.\n\
                 HiddenServiceDir /var/lib/tor/umbra-relay/\n\
                 HiddenServicePort 9910 127.0.0.1:9910   # group\n\
                 HiddenServicePort 9900 127.0.0.1:9900   # mailbox\n\
                 HiddenServicePort 9930 127.0.0.1:9930   # call\n\
                 # Give clients the generated <HiddenServiceDir>/hostname (.onion).\n";
    let _ = std::fs::write(relay.join("umbra-relay.toml"), cfg);
    let _ = std::fs::write(relay.join("torrc.onion.sample"), torrc);
    println!("wrote {}\\umbra-relay.toml (private_mode) + torrc.onion.sample", relay.display());
}

/// The set of files in `dir` that should be covered by the integrity manifest:
/// the given binaries (with platform exe suffix) plus any SymCrypt runtime lib.
fn signable(dir: &Path, bins: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for b in bins {
        let f = exe(b);
        if dir.join(&f).exists() {
            v.push(f);
        }
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n == "symcrypt.dll" || n.starts_with("libsymcrypt.so") {
                v.push(n);
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

/// Sign the integrity manifest over `files` in `dir` via the umbra-manifest tool.
fn sign_dir(root: &Path, dir: &Path, files: &[String], key: &Path) {
    if files.is_empty() {
        return;
    }
    let common = root.join("unichat-common");
    run("cargo", &["build", "--release", "-p", "umbra-manifest"], &common, &BTreeMap::new());
    let tool = common.join("target").join("release").join(exe("umbra-manifest"));
    let mut args: Vec<String> = vec![
        "sign".into(),
        key.to_string_lossy().into_owned(),
        dir.to_string_lossy().into_owned(),
    ];
    args.extend(files.iter().cloned());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&tool.to_string_lossy(), &arg_refs, root, &BTreeMap::new());
}

fn exe(name: &str) -> String {
    if is_windows() {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// Copy the built binaries + SymCrypt lib + manifest + docs into a staging dir
/// and produce a portable archive.
fn package(root: &Path, bin_dir: &Path, bins: &[&str], variant: &str, o: &Opts) {
    let out = o.out.clone().unwrap_or_else(|| root.join("dist"));
    std::fs::create_dir_all(&out).ok();
    let os = if is_windows() { "windows" } else { "linux" };
    let stage_name = format!("umbra-{variant}-{os}");
    let stage = out.join(&stage_name);
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).unwrap_or_else(|e| fail(&format!("staging: {e}")));

    // binaries
    for b in bins {
        let src = bin_dir.join(exe(b));
        if src.exists() {
            copy_into(&src, &stage);
        }
    }
    // SymCrypt runtime lib(s) next to the binaries
    let vendor = root.join("unichat-common").join("vendor").join("symcrypt");
    let libdir = if is_windows() { vendor.join("dll") } else { vendor.join("linux") };
    if let Ok(rd) = std::fs::read_dir(&libdir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n == "symcrypt.dll" || n.starts_with("libsymcrypt.so") {
                copy_into(&e.path(), &stage);
            }
        }
    }
    // docs + hardening scripts (the manifest is generated in-stage below)
    for doc in [
        "README.md",
        "LICENSE",
        "docs/INSTALL.md",
        "docs/USAGE.md",
        "unichat-common/docs/hardening.md",
    ] {
        let p = root.join(doc);
        if p.exists() {
            copy_into(&p, &stage);
        }
    }
    // A Linux launcher that sets LD_LIBRARY_PATH to the archive dir (belt and
    // braces alongside the rpath=$ORIGIN baked in at link time).
    if !is_windows() {
        let launcher = "#!/bin/sh\ncd \"$(dirname \"$0\")\"\nexport LD_LIBRARY_PATH=\"$(pwd):$LD_LIBRARY_PATH\"\nexec ./umbra \"$@\"\n";
        let lp = stage.join("umbra.sh");
        let _ = std::fs::write(&lp, launcher);
    }

    // If signing, generate the manifest over the STAGED files so the archive is
    // self-verifying (covers the binaries + the SymCrypt runtime lib together).
    if let Some(key) = &o.sign_key {
        let files = signable(&stage, bins);
        sign_dir(root, &stage, &files, key);
    }

    // archive
    let archive = if is_windows() {
        out.join(format!("{stage_name}.zip"))
    } else {
        out.join(format!("{stage_name}.tar.gz"))
    };
    let _ = std::fs::remove_file(&archive);
    if is_windows() {
        // bsdtar (Windows 10+) infers zip from the extension with -a.
        run("tar", &["-a", "-c", "-f", &archive.to_string_lossy(), "-C", &out.to_string_lossy(), &stage_name], root, &BTreeMap::new());
    } else {
        run("tar", &["czf", &archive.to_string_lossy(), "-C", &out.to_string_lossy(), &stage_name], root, &BTreeMap::new());
    }
    println!("\n✔ packaged {}", archive.display());
}

fn copy_into(src: &Path, dir: &Path) {
    let dst = dir.join(src.file_name().unwrap());
    if let Some(p) = dst.parent() {
        std::fs::create_dir_all(p).ok();
    }
    std::fs::copy(src, &dst).unwrap_or_else(|e| fail(&format!("copy {}: {e}", src.display())));
}

fn main() {
    let o = parse_args();
    let root = repo_root();
    println!("umbra-build: repo {}", root.display());
    println!(
        "variant: {} {} {}",
        if o.torify { "TORIFY" } else { "non-Tor" },
        o.target,
        if o.release { "release" } else { "debug" }
    );

    let symcrypt = ensure_symcrypt(&root, &o);
    let env = build_env(&symcrypt);
    let variant = if o.torify { "tor" } else { "notor" };

    let do_app = o.target == "app" || o.target == "all";
    let do_relay = o.target == "relay" || o.target == "all";

    if do_app {
        let bin_dir = build_app(&root, &o, &env);
        let bins = ["umbra", "unichat"];
        if o.package {
            package(&root, &bin_dir, &bins, &format!("{variant}-app"), &o);
        } else if let Some(key) = &o.sign_key {
            sign_dir(&root, &bin_dir, &signable(&bin_dir, &bins), key);
        }
    }
    if do_relay {
        let relay = o
            .relay_path
            .clone()
            .unwrap_or_else(|| root.parent().map(|p| p.join("umbra-relay")).unwrap_or_else(|| root.join("../umbra-relay")));
        let bin_dir = build_relay(&relay, &o, &env);
        let bins = ["umbra-relay"];
        if o.package {
            package(&root, &bin_dir, &bins, &format!("{variant}-relay"), &o);
        } else if let Some(key) = &o.sign_key {
            sign_dir(&root, &bin_dir, &signable(&bin_dir, &bins), key);
        }
    }

    println!("\n✔ done.");
}
