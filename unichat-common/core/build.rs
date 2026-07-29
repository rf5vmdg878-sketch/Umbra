use std::path::Path;

// symcrypt.dll must be findable at run time by every executable that links
// unichat-core (binaries in target/<profile>/, test executables in
// target/<profile>/deps/). Copy the vendored DLL next to both.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let dll = Path::new(&manifest)
        .parent()
        .unwrap()
        .join("vendor/symcrypt/dll/symcrypt.dll");
    if !dll.exists() {
        println!(
            "cargo:warning=vendored symcrypt.dll not found at {}; \
             executables will fail to start unless symcrypt.dll is on PATH",
            dll.display()
        );
        return;
    }

    // OUT_DIR = <target>/<profile>/build/<pkg>-<hash>/out
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let profile_dir = Path::new(&out_dir).ancestors().nth(3).unwrap();
    for dest in [
        profile_dir.join("symcrypt.dll"),
        profile_dir.join("deps").join("symcrypt.dll"),
    ] {
        if let Some(parent) = dest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::copy(&dll, &dest);
    }
}
