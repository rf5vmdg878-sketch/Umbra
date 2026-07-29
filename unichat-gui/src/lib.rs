//! Umbra — the shared branded GUI for the unified secure communications suite.
//!
//! One crate, both forks: the no-Tor fork builds it plain; the Tor fork builds
//! it with `--features tor` to light up the onion-transport controls. The window
//! never blocks — all core work runs on [`engine`]'s background thread.

mod app;
mod engine;
mod theme;
mod widgets;

#[cfg(feature = "tor")]
mod tor_ep;

/// Which transports this build offers (the Tor fork passes `tor_available: true`).
#[derive(Clone, Copy)]
pub struct Build {
    pub tor_available: bool,
}

/// Launch the Umbra window. Returns when the window closes.
pub fn run(build: Build) -> Result<(), String> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1180.0, 760.0])
        .with_min_inner_size([900.0, 580.0])
        .with_title("Umbra");
    // The eclipse mark as the window / taskbar icon.
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/umbra-256.png")) {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "Umbra",
        options,
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            Ok(Box::new(app::App::new(build)))
        }),
    )
    .map_err(|e| e.to_string())
}
