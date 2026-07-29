//! Umbra visual identity applied to egui — the "night instrument" palette.

use egui::{Color32, CornerRadius, Stroke, Visuals};

// Brand tokens (see the brand plan). Ink ground, corona-gold accent.
pub const INK: Color32 = Color32::from_rgb(0x0A, 0x0E, 0x17);
pub const INK_2: Color32 = Color32::from_rgb(0x0D, 0x12, 0x20);
pub const SURFACE: Color32 = Color32::from_rgb(0x12, 0x18, 0x26);
pub const SURFACE_2: Color32 = Color32::from_rgb(0x16, 0x1D, 0x2E);
pub const LINE: Color32 = Color32::from_rgb(0x23, 0x2C, 0x40);
pub const LINE_2: Color32 = Color32::from_rgb(0x2E, 0x39, 0x50);
pub const TEXT: Color32 = Color32::from_rgb(0xE7, 0xEC, 0xF5);
pub const MUTED: Color32 = Color32::from_rgb(0x98, 0xA2, 0xB8);
pub const FAINT: Color32 = Color32::from_rgb(0x6B, 0x75, 0x90);
pub const CORONA: Color32 = Color32::from_rgb(0xE8, 0xB1, 0x5A);
pub const CYAN: Color32 = Color32::from_rgb(0x5A, 0xC8, 0xD8);
pub const QUANTUM: Color32 = Color32::from_rgb(0x9B, 0x8C, 0xFF);
pub const GOOD: Color32 = Color32::from_rgb(0x4F, 0xB4, 0x77);
pub const WARN: Color32 = Color32::from_rgb(0xE8, 0x93, 0x3A);
pub const BAD: Color32 = Color32::from_rgb(0xE5, 0x48, 0x4D);

pub fn install(ctx: &egui::Context) {
    let mut v = Visuals::dark();
    v.override_text_color = Some(TEXT);
    v.panel_fill = INK;
    v.window_fill = SURFACE;
    v.extreme_bg_color = INK_2;
    v.faint_bg_color = SURFACE_2;
    v.hyperlink_color = CYAN;
    v.selection.bg_fill = Color32::from_rgb(0x2a, 0x24, 0x13);
    v.selection.stroke = Stroke::new(1.0, CORONA);

    let r = CornerRadius::same(7);
    v.widgets.noninteractive.bg_fill = SURFACE;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, MUTED);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
    v.widgets.noninteractive.corner_radius = r;

    v.widgets.inactive.bg_fill = SURFACE_2;
    v.widgets.inactive.weak_bg_fill = SURFACE_2;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, LINE_2);
    v.widgets.inactive.corner_radius = r;

    v.widgets.hovered.bg_fill = Color32::from_rgb(0x1c, 0x24, 0x38);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x1c, 0x24, 0x38);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, CORONA);
    v.widgets.hovered.corner_radius = r;

    v.widgets.active.bg_fill = Color32::from_rgb(0x2a, 0x24, 0x13);
    v.widgets.active.weak_bg_fill = Color32::from_rgb(0x2a, 0x24, 0x13);
    v.widgets.active.fg_stroke = Stroke::new(1.0, CORONA);
    v.widgets.active.bg_stroke = Stroke::new(1.0, CORONA);
    v.widgets.active.corner_radius = r;

    ctx.set_visuals(v);

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
    });
}
