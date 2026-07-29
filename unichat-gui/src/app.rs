//! The Umbra application window: lock screen, left-nav shell, per-feature
//! screens, an always-present security inspector, and an extensive settings
//! screen. All real work is delegated to the background [`crate::engine`].

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use egui::{Align, Layout, RichText, ScrollArea, Stroke};
use zeroize::Zeroizing;

use crate::engine::{
    Command, ContactView, EngineHandle, Event, Level, MessageView, ProfileView,
};
use crate::theme;
use crate::widgets::{accent_button, copy_button, eyebrow, fingerprint, kv, mono, pill};
use crate::Build;

#[derive(Clone, Copy, PartialEq)]
enum Screen {
    Identity,
    Contacts,
    Groups,
    Mailbox,
    Calls,
    Servers,
    Settings,
}

pub struct App {
    build: Build,
    engine: EngineHandle,

    profile: Option<ProfileView>,
    contacts: Vec<ContactView>,
    groups: Vec<crate::engine::GroupView>,
    group_threads: HashMap<String, Vec<MessageView>>,
    inbox: Vec<MessageView>,
    servers: Vec<(String, String)>,
    screen: Screen,
    selected_group: Option<String>,

    status: String,
    status_level: Level,

    store_path: String,
    profile_name: String,
    passphrase: String,
    creating: bool,

    new_pass: String,
    add_alias: String,
    add_bundle: String,
    new_group: String,
    join_desc: String,
    relay_addr: String,
    group_compose: String,
    mailbox_addr: String,
    msg_alias: String,
    msg_text: String,
    mailbox_bind: String,
    relay_bind: String,

    call_relay: String,
    call_id: String,
    call_file: String,
    call_out: String,
    call_video: bool,
    call_seconds: u32,
    /// Latest decoded incoming video frame from a live call.
    call_texture: Option<egui::TextureHandle>,
    in_call: bool,

    use_tor: bool,
    text_size: f32,
    show_inspector: bool,
    notify_preview: bool,
    raw_crypto: bool,
    applied_scale: bool,

    // Sanitize / factory-reset (Settings → Maintenance).
    sanitize_profiles: bool,
    sanitize_tor: bool,
    sanitize_confirm: bool,
}

impl App {
    pub fn new(build: Build) -> Self {
        let default_store = std::env::temp_dir()
            .join("umbra.profile")
            .to_string_lossy()
            .into_owned();
        Self {
            build,
            engine: crate::engine::spawn(),
            profile: None,
            contacts: Vec::new(),
            groups: Vec::new(),
            group_threads: HashMap::new(),
            inbox: Vec::new(),
            servers: Vec::new(),
            screen: Screen::Identity,
            selected_group: None,
            status: "locked - create or unlock a profile".into(),
            status_level: Level::Info,
            store_path: default_store,
            profile_name: String::new(),
            passphrase: String::new(),
            creating: false,
            new_pass: String::new(),
            add_alias: String::new(),
            add_bundle: String::new(),
            new_group: String::new(),
            join_desc: String::new(),
            relay_addr: "127.0.0.1:9910".into(),
            group_compose: String::new(),
            mailbox_addr: "127.0.0.1:9900".into(),
            msg_alias: String::new(),
            msg_text: String::new(),
            mailbox_bind: "127.0.0.1:9900".into(),
            relay_bind: "127.0.0.1:9910".into(),
            call_relay: "127.0.0.1:9930".into(),
            call_id: String::new(),
            call_texture: None,
            in_call: false,
            call_file: String::new(),
            call_out: std::env::temp_dir().join("umbra-inbox").to_string_lossy().into_owned(),
            call_video: false,
            call_seconds: 5,
            use_tor: false,
            text_size: 15.0,
            show_inspector: true,
            notify_preview: false,
            raw_crypto: false,
            applied_scale: false,
            sanitize_profiles: true,
            sanitize_tor: true,
            sanitize_confirm: false,
        }
    }

    fn send(&self, cmd: Command) {
        let _ = self.engine.tx.send(cmd);
    }

    fn drain_events(&mut self, ctx: &egui::Context) {
        while let Ok(ev) = self.engine.rx.try_recv() {
            match ev {
                Event::Status(msg, level) => {
                    self.status = msg;
                    self.status_level = level;
                }
                Event::VideoFrame { width, height, rgba } => {
                    self.in_call = true;
                    let img = egui::ColorImage::from_rgba_unmultiplied(
                        [width as usize, height as usize],
                        &rgba,
                    );
                    match &mut self.call_texture {
                        Some(tex) => tex.set(img, egui::TextureOptions::LINEAR),
                        None => {
                            self.call_texture =
                                Some(ctx.load_texture("call_video", img, egui::TextureOptions::LINEAR));
                        }
                    }
                }
                Event::CallEnded => {
                    self.in_call = false;
                }
                Event::Unlocked(p) => {
                    self.profile = Some(p);
                    self.screen = Screen::Identity;
                    self.passphrase.clear();
                }
                Event::Locked => {
                    self.profile = None;
                    self.contacts.clear();
                    self.groups.clear();
                    self.group_threads.clear();
                    self.inbox.clear();
                    self.selected_group = None;
                }
                Event::Contacts(c) => self.contacts = c,
                Event::Groups(g) => {
                    if self.selected_group.is_none() {
                        self.selected_group = g.first().map(|x| x.name.clone());
                    }
                    self.groups = g;
                }
                Event::GroupThread { group, messages } => {
                    self.group_threads.insert(group, messages);
                }
                Event::Inbox(m) => self.inbox = m,
                Event::ServerUp { kind, addr } => {
                    self.servers.push((kind, addr));
                }
            }
        }
    }
}

fn level_color(l: Level) -> egui::Color32 {
    match l {
        Level::Info => theme::MUTED,
        Level::Good => theme::GOOD,
        Level::Warn => theme::WARN,
        Level::Bad => theme::BAD,
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if !self.applied_scale {
            self.applied_scale = true;
        }
        ctx.request_repaint_after(Duration::from_millis(150));
        self.drain_events(&ctx);

        if self.profile.is_none() {
            self.lock_screen(ui);
            return;
        }

        egui::Panel::top("titlebar")
            .frame(
                egui::Frame::NONE
                    .fill(theme::SURFACE)
                    .inner_margin(egui::Margin::symmetric(14, 9)),
            )
            .show(ui, |ui| self.titlebar(ui));

        egui::Panel::bottom("statusbar")
            .frame(
                egui::Frame::NONE
                    .fill(theme::INK_2)
                    .inner_margin(egui::Margin::symmetric(14, 6)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("*")
                            .color(level_color(self.status_level))
                            .size(12.0),
                    );
                    ui.label(RichText::new(&self.status).color(theme::MUTED).size(12.5));
                });
            });

        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(206.0)
            .frame(
                egui::Frame::NONE
                    .fill(theme::INK_2)
                    .inner_margin(egui::Margin::same(12)),
            )
            .show(ui, |ui| self.nav(ui));

        if self.show_inspector {
            egui::Panel::right("inspector")
                .resizable(false)
                .exact_size(244.0)
                .frame(
                    egui::Frame::NONE
                        .fill(theme::INK_2)
                        .inner_margin(egui::Margin::same(14)),
                )
                .show(ui, |ui| self.inspector(ui));
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::INK)
                    .inner_margin(egui::Margin::same(18)),
            )
            .show(ui, |ui| {
                ScrollArea::vertical().show(ui, |ui| match self.screen {
                    Screen::Identity => self.identity_screen(ui),
                    Screen::Contacts => self.contacts_screen(ui),
                    Screen::Groups => self.groups_screen(ui),
                    Screen::Mailbox => self.mailbox_screen(ui),
                    Screen::Calls => self.calls_screen(ui),
                    Screen::Servers => self.servers_screen(ui),
                    Screen::Settings => self.settings_screen(ui),
                });
            });
    }
}

impl App {
    fn lock_screen(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::INK)
                    .inner_margin(egui::Margin::same(40)),
            )
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(48.0);
                    ui.label(
                        RichText::new("U M B R A")
                            .monospace()
                            .size(40.0)
                            .color(theme::TEXT)
                            .strong(),
                    );
                    ui.label(
                        RichText::new("post-quantum . onion-routed")
                            .color(theme::CORONA)
                            .size(13.0),
                    );
                    ui.add_space(4.0);
                    pill(
                        ui,
                        if self.build.tor_available {
                            "TOR BUILD"
                        } else {
                            "DIRECT-TCP BUILD"
                        },
                        if self.build.tor_available {
                            theme::CYAN
                        } else {
                            theme::MUTED
                        },
                    );
                    ui.add_space(26.0);
                });
                ui.vertical_centered(|ui| {
                    let w = 420.0_f32.min(ui.available_width());
                    ui.allocate_ui_with_layout(
                        egui::vec2(w, 0.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.group(|ui| {
                                ui.set_width(w - 24.0);
                                eyebrow(ui, "Profile store");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.store_path)
                                        .desired_width(f32::INFINITY)
                                        .hint_text("path to .profile"),
                                );
                                ui.add_space(8.0);
                                if self.creating {
                                    eyebrow(ui, "Display name");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.profile_name)
                                            .desired_width(f32::INFINITY)
                                            .hint_text("your display name"),
                                    );
                                    ui.add_space(8.0);
                                }
                                eyebrow(ui, "Passphrase");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.passphrase)
                                        .password(true)
                                        .desired_width(f32::INFINITY)
                                        .hint_text("unlocks your encrypted profile"),
                                );
                                ui.add_space(14.0);
                                ui.horizontal(|ui| {
                                    if self.creating {
                                        if accent_button(ui, "Create profile").clicked() {
                                            let path = PathBuf::from(self.store_path.trim());
                                            let name = self.profile_name.trim().to_string();
                                            let passphrase =
                                                Zeroizing::new(std::mem::take(&mut self.passphrase));
                                            self.send(Command::CreateProfile { path, name, passphrase });
                                        }
                                        if ui.button("Back to unlock").clicked() {
                                            self.creating = false;
                                        }
                                    } else {
                                        if accent_button(ui, "Unlock").clicked() {
                                            let path = PathBuf::from(self.store_path.trim());
                                            let passphrase =
                                                Zeroizing::new(std::mem::take(&mut self.passphrase));
                                            self.send(Command::Unlock { path, passphrase });
                                        }
                                        if ui.button("Create new profile").clicked() {
                                            self.creating = true;
                                        }
                                    }
                                });
                            });
                            ui.add_space(10.0);
                            ui.label(
                                RichText::new(&self.status)
                                    .color(level_color(self.status_level))
                                    .size(12.0),
                            );
                        },
                    );
                });
            });
    }

    fn titlebar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("UMBRA")
                    .monospace()
                    .strong()
                    .size(15.0)
                    .color(theme::TEXT),
            );
            ui.label(RichText::new("(eclipse)").color(theme::CORONA).size(11.0));
            if self.use_tor && self.build.tor_available {
                pill(ui, "TOR", theme::CYAN);
            } else {
                pill(ui, "TCP", theme::MUTED);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Lock").clicked() {
                    self.send(Command::Lock);
                }
                if let Some(p) = &self.profile {
                    ui.label(
                        RichText::new(format!("* {}", p.name))
                            .color(theme::GOOD)
                            .size(12.5),
                    );
                }
            });
        });
    }

    fn nav(&mut self, ui: &mut egui::Ui) {
        if let Some(p) = &self.profile {
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(format!("* {}", p.name))
                        .strong()
                        .color(theme::TEXT),
                );
                ui.label(mono(&p.fingerprint).size(10.5).color(theme::FAINT));
            });
        }
        ui.add_space(8.0);
        let items = [
            (Screen::Identity, "Identity"),
            (Screen::Contacts, "Contacts"),
            (Screen::Groups, "Groups"),
            (Screen::Mailbox, "Mailbox"),
            (Screen::Calls, "Calls"),
            (Screen::Servers, "Servers"),
            (Screen::Settings, "Settings"),
        ];
        for (scr, label) in items {
            let count = match scr {
                Screen::Contacts => self.contacts.len(),
                Screen::Groups => self.groups.len(),
                Screen::Mailbox => self.inbox.len(),
                _ => 0,
            };
            let text = if count > 0 {
                format!("{label}   ({count})")
            } else {
                label.to_string()
            };
            if ui
                .selectable_label(self.screen == scr, RichText::new(text).size(14.0))
                .clicked()
            {
                self.screen = scr;
            }
        }
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            if ui.button("Lock now").clicked() {
                self.send(Command::Lock);
            }
        });
    }

    fn inspector(&mut self, ui: &mut egui::Ui) {
        eyebrow(ui, "Security");
        ui.add_space(6.0);
        kv(ui, "Key exchange", "X-Wing hybrid", theme::QUANTUM);
        kv(ui, "PQ + classical", "ML-KEM768.X25519", theme::QUANTUM);
        kv(ui, "Cipher", "AES-256-GCM", theme::TEXT);
        kv(ui, "At rest", "Argon2id", theme::TEXT);
        kv(
            ui,
            "Transport",
            if self.use_tor && self.build.tor_available {
                "onion v3"
            } else {
                "direct TCP"
            },
            if self.use_tor && self.build.tor_available {
                theme::CYAN
            } else {
                theme::MUTED
            },
        );
        ui.add_space(14.0);
        eyebrow(ui, "This profile");
        ui.add_space(6.0);
        if let Some(p) = self.profile.clone() {
            ui.label(
                RichText::new("Your fingerprint")
                    .color(theme::MUTED)
                    .size(12.0),
            );
            fingerprint(ui, &p.fingerprint);
            ui.add_space(6.0);
            copy_button(ui, "Copy bundle", &p.bundle);
        }
        if self.screen == Screen::Groups {
            if let Some(g) = self.selected_group.clone() {
                ui.add_space(14.0);
                eyebrow(ui, "Group");
                ui.label(RichText::new(&g).color(theme::TEXT));
                let msgs = self.group_threads.get(&g).map(|v| v.len()).unwrap_or(0);
                kv(ui, "messages", &msgs.to_string(), theme::TEXT);
                kv(ui, "relay trust", "none (sealed)", theme::GOOD);
            }
        }
    }

    fn screen_title(ui: &mut egui::Ui, eyebrow_text: &str, title: &str) {
        eyebrow(ui, eyebrow_text);
        ui.label(RichText::new(title).size(22.0).strong().color(theme::TEXT));
        ui.add_space(12.0);
    }

    fn identity_screen(&mut self, ui: &mut egui::Ui) {
        Self::screen_title(ui, "who you are", "Identity");
        let Some(p) = self.profile.clone() else {
            return;
        };
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            kv(ui, "Display name", &p.name, theme::TEXT);
            ui.add_space(4.0);
            ui.label(
                RichText::new("Fingerprint - read this aloud to verify in person")
                    .color(theme::MUTED)
                    .size(12.0),
            );
            fingerprint(ui, &p.fingerprint);
            ui.add_space(6.0);
            kv(ui, "Key derivation", &p.kdf, theme::TEXT);
        });
        ui.add_space(12.0);
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Your bundle");
            ui.label(
                RichText::new(
                    "Share this so others can add you. It's a signed public key - safe to send in the open.",
                )
                .color(theme::MUTED)
                .size(12.0),
            );
            ui.add_space(6.0);
            let mut bundle = p.bundle.clone();
            ui.add(
                egui::TextEdit::multiline(&mut bundle)
                    .desired_width(f32::INFINITY)
                    .desired_rows(3)
                    .font(egui::TextStyle::Monospace),
            );
            ui.add_space(6.0);
            copy_button(ui, "Copy bundle", &p.bundle);
        });
        ui.add_space(12.0);
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Change passphrase");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_pass)
                        .password(true)
                        .hint_text("new passphrase")
                        .desired_width(240.0),
                );
                if ui.button("Change").clicked() && !self.new_pass.is_empty() {
                    let new = Zeroizing::new(std::mem::take(&mut self.new_pass));
                    self.send(Command::ChangePassphrase { new });
                }
            });
            ui.label(
                RichText::new("Re-wraps the master key; your data is never re-encrypted or weakened.")
                    .color(theme::FAINT)
                    .size(11.5),
            );
        });
    }

    fn contacts_screen(&mut self, ui: &mut egui::Ui) {
        Self::screen_title(ui, "people you trust", "Contacts");
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Add a contact");
            ui.horizontal(|ui| {
                ui.label("Alias");
                ui.add(
                    egui::TextEdit::singleline(&mut self.add_alias)
                        .desired_width(140.0)
                        .hint_text("name"),
                );
            });
            ui.add(
                egui::TextEdit::multiline(&mut self.add_bundle)
                    .desired_width(f32::INFINITY)
                    .desired_rows(2)
                    .hint_text("paste their unichat-bundle-v1:...")
                    .font(egui::TextStyle::Monospace),
            );
            ui.add_space(6.0);
            if accent_button(ui, "Add contact").clicked() {
                let alias = self.add_alias.trim().to_string();
                let bundle = std::mem::take(&mut self.add_bundle);
                self.send(Command::AddContact { alias, bundle });
                self.add_alias.clear();
            }
        });
        ui.add_space(12.0);
        if self.contacts.is_empty() {
            ui.label(RichText::new("No contacts yet.").color(theme::FAINT));
        }
        let contacts = self.contacts.clone();
        for c in &contacts {
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&c.alias).strong().color(theme::TEXT));
                    if c.verified {
                        pill(ui, "VERIFIED", theme::GOOD);
                    } else {
                        pill(ui, "UNVERIFIED", theme::WARN);
                    }
                    pill(ui, &c.state.to_uppercase(), theme::MUTED);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button("Remove").clicked() {
                            self.send(Command::RemoveContact {
                                alias: c.alias.clone(),
                            });
                        }
                        let label = if c.verified { "Unverify" } else { "Mark verified" };
                        if ui.button(label).clicked() {
                            self.send(Command::SetVerified {
                                alias: c.alias.clone(),
                                verified: !c.verified,
                            });
                        }
                    });
                });
                fingerprint(ui, &c.fingerprint);
            });
            ui.add_space(6.0);
        }
    }

    fn groups_screen(&mut self, ui: &mut egui::Ui) {
        Self::screen_title(ui, "untrusted-relay chat", "Groups");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.new_group)
                    .desired_width(160.0)
                    .hint_text("new group name"),
            );
            if ui.button("Create").clicked() && !self.new_group.trim().is_empty() {
                let name = std::mem::take(&mut self.new_group);
                self.send(Command::CreateGroup { name });
            }
            ui.separator();
            ui.add(
                egui::TextEdit::singleline(&mut self.join_desc)
                    .desired_width(200.0)
                    .hint_text("paste invite descriptor"),
            );
            if ui.button("Join").clicked() && !self.join_desc.trim().is_empty() {
                let descriptor = std::mem::take(&mut self.join_desc);
                self.send(Command::JoinGroup { descriptor });
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Relay");
            ui.add(
                egui::TextEdit::singleline(&mut self.relay_addr)
                    .desired_width(180.0)
                    .hint_text("host:port"),
            );
        });
        ui.add_space(10.0);
        ui.separator();
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(180.0);
                eyebrow(ui, "Your groups");
                let groups = self.groups.clone();
                for g in &groups {
                    let sel = self.selected_group.as_deref() == Some(g.name.as_str());
                    if ui
                        .selectable_label(sel, RichText::new(&g.name).size(14.0))
                        .clicked()
                    {
                        self.selected_group = Some(g.name.clone());
                    }
                }
            });
            ui.separator();
            ui.vertical(|ui| {
                let Some(gname) = self.selected_group.clone() else {
                    ui.label(RichText::new("Select or create a group.").color(theme::FAINT));
                    return;
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&gname).strong().color(theme::TEXT));
                    pill(ui, "SEALED TO RELAY", theme::GOOD);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button("Fetch").clicked() {
                            self.send(Command::GroupFetch {
                                group: gname.clone(),
                                relay: self.relay_addr.trim().to_string(),
                            });
                        }
                        if let Some(g) = self.groups.iter().find(|g| g.name == gname) {
                            let d = g.descriptor.clone();
                            if ui.button("Copy invite").clicked() {
                                ui.ctx().copy_text(d);
                            }
                        }
                        if ui.button("Leave").clicked() {
                            self.send(Command::LeaveGroup {
                                name: gname.clone(),
                            });
                            self.selected_group = None;
                        }
                    });
                });
                ui.add_space(6.0);
                egui::Frame::NONE
                    .fill(theme::INK_2)
                    .corner_radius(egui::CornerRadius::same(8))
                    .inner_margin(egui::Margin::same(10))
                    .stroke(Stroke::new(1.0, theme::LINE))
                    .show(ui, |ui| {
                        ui.set_min_height(220.0);
                        ui.set_width(ui.available_width());
                        ScrollArea::vertical()
                            .max_height(240.0)
                            .auto_shrink([false, false])
                            .show(ui, |ui| match self.group_threads.get(&gname) {
                                Some(msgs) if !msgs.is_empty() => {
                                    for m in msgs {
                                        message_bubble(ui, m);
                                    }
                                }
                                _ => {
                                    ui.label(
                                        RichText::new("No messages fetched yet. Press Fetch.")
                                            .color(theme::FAINT),
                                    );
                                }
                            });
                    });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let avail = (ui.available_width() - 80.0).max(120.0);
                    let te = ui.add(
                        egui::TextEdit::singleline(&mut self.group_compose)
                            .desired_width(avail)
                            .hint_text("message the group..."),
                    );
                    let enter =
                        te.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (accent_button(ui, "Post").clicked() || enter)
                        && !self.group_compose.trim().is_empty()
                    {
                        let relay = self.relay_addr.trim().to_string();
                        let text = std::mem::take(&mut self.group_compose);
                        self.send(Command::GroupPost {
                            group: gname.clone(),
                            relay,
                            text,
                        });
                    }
                });
            });
        });
    }

    fn mailbox_screen(&mut self, ui: &mut egui::Ui) {
        Self::screen_title(ui, "offline store-and-forward", "Mailbox");
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Send an offline message");
            ui.horizontal(|ui| {
                ui.label("To");
                egui::ComboBox::from_id_salt("msg_to")
                    .selected_text(if self.msg_alias.is_empty() {
                        "select contact".to_string()
                    } else {
                        self.msg_alias.clone()
                    })
                    .show_ui(ui, |ui| {
                        for c in &self.contacts {
                            ui.selectable_value(
                                &mut self.msg_alias,
                                c.alias.clone(),
                                c.alias.clone(),
                            );
                        }
                    });
                ui.label("via");
                ui.add(
                    egui::TextEdit::singleline(&mut self.mailbox_addr)
                        .desired_width(150.0)
                        .hint_text("mailbox host:port"),
                );
            });
            ui.add(
                egui::TextEdit::multiline(&mut self.msg_text)
                    .desired_width(f32::INFINITY)
                    .desired_rows(2)
                    .hint_text("sealed to their long-term key..."),
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if accent_button(ui, "Send offline").clicked()
                    && !self.msg_alias.is_empty()
                    && !self.msg_text.trim().is_empty()
                {
                    let alias = self.msg_alias.clone();
                    let mailbox = self.mailbox_addr.trim().to_string();
                    let text = std::mem::take(&mut self.msg_text);
                    self.send(Command::MsgSend { alias, mailbox, text });
                }
                if ui.button("Collect mine").clicked() {
                    self.send(Command::MsgCollect {
                        mailbox: self.mailbox_addr.trim().to_string(),
                    });
                }
            });
        });
        ui.add_space(12.0);
        eyebrow(ui, "Inbox");
        if self.inbox.is_empty() {
            ui.label(
                RichText::new("No collected messages. Press \"Collect mine\".")
                    .color(theme::FAINT),
            );
        }
        let inbox = self.inbox.clone();
        egui::Frame::NONE
            .fill(theme::INK_2)
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::same(10))
            .stroke(Stroke::new(1.0, theme::LINE))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                for m in &inbox {
                    message_bubble(ui, m);
                }
            });
    }

    fn calls_screen(&mut self, ui: &mut egui::Ui) {
        Self::screen_title(ui, "e2e transfer + voice/video", "Calls");
        ui.label(
            RichText::new("Routed through your relay's call service. Agree a call-id with your peer, then one side dials/sends and the other answers/receives.")
                .color(theme::MUTED)
                .size(13.0),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Relay");
            ui.add(egui::TextEdit::singleline(&mut self.call_relay).desired_width(150.0).hint_text("host:9930"));
            ui.label("Call-id");
            ui.add(egui::TextEdit::singleline(&mut self.call_id).desired_width(160.0).hint_text("shared secret string"));
        });
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Encrypted file transfer");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.call_file).desired_width(280.0).hint_text("file to send"));
                if ui.button("Pick…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.call_file = p.to_string_lossy().into_owned();
                    }
                }
                if accent_button(ui, "Send file").clicked() && !self.call_incomplete() && !self.call_file.trim().is_empty() {
                    self.send(Command::CallSendFile {
                        relay: self.call_relay.trim().into(),
                        id: self.call_id.trim().into(),
                        file: std::path::PathBuf::from(self.call_file.trim()),
                    });
                }
            });
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.call_out).desired_width(280.0).hint_text("receive into folder"));
                if ui.button("Pick…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.call_out = p.to_string_lossy().into_owned();
                    }
                }
                if ui.button("Receive file").clicked() && !self.call_incomplete() {
                    self.send(Command::CallRecvFile {
                        relay: self.call_relay.trim().into(),
                        id: self.call_id.trim().into(),
                        out_dir: std::path::PathBuf::from(self.call_out.trim()),
                    });
                }
            });
        });
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Voice / video call");
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.call_video, "Video");
                ui.label("Duration");
                ui.add(egui::Slider::new(&mut self.call_seconds, 1..=30).suffix("s"));
            });
            ui.horizontal(|ui| {
                if accent_button(ui, "Dial").clicked() && !self.call_incomplete() {
                    self.send(Command::CallDial {
                        relay: self.call_relay.trim().into(),
                        id: self.call_id.trim().into(),
                        video: self.call_video,
                        seconds: self.call_seconds,
                    });
                }
                if ui.button("Answer").clicked() && !self.call_incomplete() {
                    self.send(Command::CallAnswer {
                        relay: self.call_relay.trim().into(),
                        id: self.call_id.trim().into(),
                        video: self.call_video,
                    });
                }
                if self.in_call {
                    ui.colored_label(theme::GOOD, "● live");
                }
            });

            // Incoming video from the peer (real camera frames, decoded).
            if let Some(tex) = &self.call_texture {
                ui.add_space(8.0);
                let avail = ui.available_width().min(480.0);
                let size = tex.size_vec2();
                let scale = (avail / size.x).min(1.0);
                ui.image(egui::load::SizedTexture::new(tex.id(), size * scale));
            }

            ui.add_space(4.0);
            ui.label(
                if cfg!(feature = "media") {
                    RichText::new("Live: captures your microphone and (if enabled) camera, plays the peer's audio, and shows their video above. All frames are end-to-end encrypted; the relay sees only ciphertext.")
                } else {
                    RichText::new("This build was compiled without the media feature — the encrypted media path runs with synthetic frames. Rebuild with --features media for real mic/camera.")
                }
                .color(theme::FAINT)
                .size(11.5),
            );
        });
    }

    /// True if the call form is missing the relay or the call-id.
    fn call_incomplete(&self) -> bool {
        self.call_relay.trim().is_empty() || self.call_id.trim().is_empty()
    }

    fn servers_screen(&mut self, ui: &mut egui::Ui) {
        Self::screen_title(ui, "self-host infrastructure", "Servers");
        ui.label(
            RichText::new(
                "Run your own untrusted mailbox and group relay. They store only sealed blobs - they can't read anything.",
            )
            .color(theme::MUTED)
            .size(13.0),
        );
        ui.add_space(10.0);
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Mailbox (store-and-forward)");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.mailbox_bind).desired_width(160.0));
                if ui.button("Start mailbox").clicked() {
                    self.send(Command::StartMailbox {
                        bind: self.mailbox_bind.trim().to_string(),
                    });
                }
            });
        });
        ui.add_space(8.0);
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Group relay");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.relay_bind).desired_width(160.0));
                if ui.button("Start relay").clicked() {
                    self.send(Command::StartRelay {
                        bind: self.relay_bind.trim().to_string(),
                    });
                }
            });
        });
        ui.add_space(12.0);
        eyebrow(ui, "Running");
        if self.servers.is_empty() {
            ui.label(RichText::new("Nothing running.").color(theme::FAINT));
        }
        let servers = self.servers.clone();
        for (kind, addr) in &servers {
            ui.horizontal(|ui| {
                pill(ui, &kind.to_uppercase(), theme::GOOD);
                ui.label(mono(addr).color(theme::TEXT));
            });
        }
    }

    fn settings_screen(&mut self, ui: &mut egui::Ui) {
        Self::screen_title(ui, "extensive control", "Settings");

        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Transport");
            if self.build.tor_available {
                if ui
                    .checkbox(&mut self.use_tor, "Route over Tor (onion v3)")
                    .changed()
                {
                    self.send(Command::SetUseTor(self.use_tor));
                }
                ui.label(
                    RichText::new("First Tor use bootstraps arti; it may take a minute.")
                        .color(theme::FAINT)
                        .size(11.5),
                );
            } else {
                ui.label(
                    RichText::new("This build is direct-TCP only. Use the Tor fork for onion routing.")
                        .color(theme::MUTED)
                        .size(12.5),
                );
            }
            ui.add_space(4.0);
            kv(ui, "Fail closed", "always (no clearnet fallback)", theme::GOOD);
        });
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Security");
            kv(ui, "Passphrase KDF", "Argon2id 64 MiB t=3 p=4", theme::TEXT);
            kv(ui, "Session forward secrecy", "per session (ephemeral)", theme::GOOD);
            ui.checkbox(&mut self.notify_preview, "Show message text in notifications");
            if ui.button("Lock now").clicked() {
                self.send(Command::Lock);
            }
        });
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Appearance");
            ui.horizontal(|ui| {
                ui.label("Text size");
                if ui
                    .add(egui::Slider::new(&mut self.text_size, 12.0..=20.0).step_by(1.0))
                    .changed()
                {
                    ui.ctx().set_pixels_per_point(self.text_size / 15.0);
                }
            });
            ui.checkbox(&mut self.show_inspector, "Show security inspector");
            ui.checkbox(&mut self.raw_crypto, "Show raw crypto readout per message");
        });
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "Maintenance");
            ui.label(
                RichText::new("Factory reset: securely wipe the selected app state back to installed defaults. This cannot be undone.")
                    .color(theme::MUTED)
                    .size(12.5),
            );
            ui.checkbox(&mut self.sanitize_profiles, "Profiles, contacts, groups & history");
            ui.checkbox(&mut self.sanitize_tor, "Tor working state (onion keys, cache)");
            ui.add_space(4.0);
            if !self.sanitize_confirm {
                let any = self.sanitize_profiles || self.sanitize_tor;
                if ui.add_enabled(any, egui::Button::new("Sanitize…")).clicked() {
                    self.sanitize_confirm = true;
                }
            } else {
                ui.horizontal(|ui| {
                    if ui
                        .button(RichText::new("Confirm wipe").color(theme::BAD))
                        .clicked()
                    {
                        self.send(Command::Sanitize {
                            store: self.store_path.trim().into(),
                            profiles: self.sanitize_profiles,
                            tor: self.sanitize_tor,
                        });
                        self.sanitize_confirm = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.sanitize_confirm = false;
                    }
                });
                ui.label(
                    RichText::new("This permanently erases the selected data and locks the app.")
                        .color(theme::WARN)
                        .size(11.5),
                );
            }
        });
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.set_width(ui.available_width());
            eyebrow(ui, "About");
            kv(
                ui,
                "Build",
                if self.build.tor_available {
                    "Tor (arti onion)"
                } else {
                    "no-Tor (direct TCP)"
                },
                theme::TEXT,
            );
            kv(ui, "Crypto", "Microsoft SymCrypt v103.11", theme::TEXT);
            kv(ui, "Suite", "phases 1-6 . 54 core tests", theme::TEXT);
        });
    }
}

fn message_bubble(ui: &mut egui::Ui, m: &MessageView) {
    let layout = if m.mine {
        Layout::right_to_left(Align::Min)
    } else {
        Layout::left_to_right(Align::Min)
    };
    ui.with_layout(layout, |ui| {
        let (fill, stroke, text_col) = if m.mine {
            (
                egui::Color32::from_rgb(0x21, 0x1d, 0x10),
                theme::CORONA.gamma_multiply(0.5),
                egui::Color32::from_rgb(0xf4, 0xe6, 0xc8),
            )
        } else {
            (theme::SURFACE_2, theme::LINE, theme::TEXT)
        };
        egui::Frame::NONE
            .fill(fill)
            .corner_radius(egui::CornerRadius::same(10))
            .inner_margin(egui::Margin::symmetric(10, 7))
            .stroke(Stroke::new(1.0, stroke))
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.set_max_width(360.0);
                    if !m.mine {
                        let who_col = if m.unknown { theme::WARN } else { theme::FAINT };
                        ui.label(RichText::new(&m.who).monospace().size(10.5).color(who_col));
                    }
                    ui.label(RichText::new(&m.body).color(text_col).size(13.5));
                });
            });
    });
    ui.add_space(4.0);
}
