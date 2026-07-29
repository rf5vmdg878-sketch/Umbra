//! Small shared UI helpers in the Umbra style.

use egui::{Color32, RichText, Stroke, Ui};

use crate::theme;

pub fn mono(s: impl Into<String>) -> RichText {
    RichText::new(s).monospace()
}

/// An uppercase, tracked-out section label.
pub fn eyebrow(ui: &mut Ui, s: &str) {
    ui.label(
        RichText::new(s.to_uppercase())
            .monospace()
            .size(10.0)
            .color(theme::FAINT),
    );
}

/// A small colored status chip.
pub fn pill(ui: &mut Ui, text: &str, color: Color32) {
    egui::Frame::NONE
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.6)))
        .corner_radius(egui::CornerRadius::same(100))
        .inner_margin(egui::Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.0).monospace().color(color));
        });
}

/// A labeled key/value row (value in mono).
pub fn kv(ui: &mut Ui, k: &str, v: &str, color: Color32) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(k).color(theme::MUTED).size(12.5));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(v).monospace().size(12.5).color(color));
        });
    });
}

/// A corona-accent primary button.
pub fn accent_button(ui: &mut Ui, label: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(label).color(theme::INK).strong()).fill(theme::CORONA))
}

/// Copy `value` to the clipboard, with a button labeled `label`.
pub fn copy_button(ui: &mut Ui, label: &str, value: &str) {
    if ui.button(label).clicked() {
        ui.ctx().copy_text(value.to_owned());
    }
}

/// Render a fingerprint as grouped mono text in the corona accent.
pub fn fingerprint(ui: &mut Ui, fp: &str) {
    ui.label(
        RichText::new(fp)
            .monospace()
            .size(12.5)
            .color(theme::CORONA),
    );
}
