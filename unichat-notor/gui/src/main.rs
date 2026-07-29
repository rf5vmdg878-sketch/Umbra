//! Umbra desktop app — no-Tor fork (direct-TCP transport only).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> Result<(), String> {
    unichat_gui::run(unichat_gui::Build {
        tor_available: false,
    })
}
