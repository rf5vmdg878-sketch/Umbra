//! Umbra desktop app — Tor fork. Tor controls light up when built with
//! `--features tor` (which pulls in the arti onion transport).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> Result<(), String> {
    unichat_gui::run(unichat_gui::Build {
        tor_available: cfg!(feature = "tor"),
    })
}
