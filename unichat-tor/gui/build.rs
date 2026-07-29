//! Embed the Umbra icon into the Windows executable (Explorer/taskbar/shortcut).

fn main() {
    #[cfg(windows)]
    {
        let ico = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../unichat-gui/assets/umbra.ico");
        println!("cargo:rerun-if-changed={}", ico.display());
        if ico.exists() {
            let mut res = winresource::WindowsResource::new();
            res.set_icon(ico.to_str().unwrap());
            if let Err(e) = res.compile() {
                println!("cargo:warning=icon embedding skipped: {e}");
            }
        }
    }
}
