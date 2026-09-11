// SPDX-License-Identifier: Apache-2.0
//!
//! sysentinel — local GTK4 front-end.
//!
//! Exists so the owner does not have to type into a chat window in a room full
//! of colleagues. It shows what the bot shows, on the machine itself.
//!
//! # It never notifies
//!
//! No desktop notifications, no popups, no badges, no sound. Ever. That is a
//! security property and not an oversight, and it is the same reasoning as the
//! duress handling in `daemon/src/facenn.rs`:
//!
//! > If somebody is standing over the owner, a machine that pops
//! > "ROSTRO NO REGISTRADO" onto the screen has just announced that it informed
//! > on them, and the owner is the one who pays for it.
//!
//! Alerts stay on the out-of-band channel, where only the owner's phone sees
//! them. This window is somewhere you *go and look*, on purpose and in your own
//! time. Nothing in this file may ever call `gio::Notification`.
//!
//! # It proves nothing about who is using it
//!
//! This runs on the machine being watched, so it is worth exactly as much as
//! the session it runs in. Anyone at an unlocked desktop is "the owner" as far
//! as this window can tell. That is why destructive operations still go through
//! the ARM → confirm ritual on the out-of-band channel, and why the phone
//! front-end — which can hold a key this machine cannot reach — is the one that
//! gets to replace a typed code.

mod ipc;

use std::path::PathBuf;
use std::time::Duration;

use adw::prelude::*;
use gtk4::glib;
use libadwaita as adw;

const APP_ID: &str = "org.sysentinel.Gui";

/// One thing the sidebar can show.
#[derive(Clone)]
struct Panel {
    id: &'static str,
    title: &'static str,
    subtitle: &'static str,
    icon: &'static str,
    request: ipc::Request,
}

const PANELS: &[Panel] = &[
    Panel {
        id: "status",
        title: "Estado",
        subtitle: "hardware y contadores",
        icon: "utilities-system-monitor-symbolic",
        request: ipc::Request::Status,
    },
    Panel {
        id: "pmu",
        title: "PMU",
        subtitle: "IPC per core type",
        icon: "speedometer-symbolic",
        request: ipc::Request::Pmu,
    },
    Panel {
        id: "ring3",
        title: "Ring −3",
        subtitle: "ME / PSP / TPM",
        icon: "security-high-symbolic",
        request: ipc::Request::Ring3,
    },
    Panel {
        id: "mei",
        title: "Superficie MEI",
        subtitle: "firmware clients",
        icon: "network-wired-symbolic",
        request: ipc::Request::Mei,
    },
    Panel {
        id: "presence",
        title: "Presencia",
        subtitle: "sensores y circunstancias",
        icon: "camera-web-symbolic",
        request: ipc::Request::Presence,
    },
    Panel {
        id: "volumes",
        title: "Volumes",
        subtitle: "what is on each disk",
        icon: "drive-harddisk-symbolic",
        request: ipc::Request::Volumes,
    },
    Panel {
        id: "face",
        title: "Rostro",
        subtitle: "motor y enrolamientos",
        icon: "avatar-default-symbolic",
        request: ipc::Request::Face,
    },
];

/// Dark, monospace, one accent. Deliberately plain: this is an instrument
/// panel, and an instrument panel that decorates itself is harder to read.
const CSS: &str = "
window { background: #0b0f14; }
.readout {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 12px;
    color: #c8d6e5;
    background: #0b0f14;
}
.readout-frame { background: #0b0f14; border: 1px solid #1c2733; border-radius: 8px; }
.panel-title { font-weight: 700; letter-spacing: 0.08em; color: #7fd4ff; }
.hint { color: #6b7c8f; font-size: 11px; }
.online  { color: #4ade80; font-weight: 700; }
.offline { color: #f87171; font-weight: 700; }
.quiet-badge {
    color: #6b7c8f; font-size: 10px; letter-spacing: 0.12em;
    border: 1px solid #1c2733; border-radius: 6px; padding: 2px 8px;
}
";

fn main() -> glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_startup(|_| {
        let provider = gtk4::CssProvider::new();
        provider.load_from_data(CSS);
        if let Some(display) = gtk4::gdk::Display::default() {
            gtk4::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    });
    app.connect_activate(build_ui);
    app.run()
}

fn build_ui(app: &adw::Application) {
    // Dark by default: this is a panel you glance at, often in a dim room.
    if let Some(manager) = adw::StyleManager::default().into() {
        let m: adw::StyleManager = manager;
        m.set_color_scheme(adw::ColorScheme::ForceDark);
    }

    let socket: PathBuf = std::env::var("SYSENTINEL_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| ipc::default_socket_path());

    let readout = gtk4::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::None)
        .left_margin(14)
        .right_margin(14)
        .top_margin(12)
        .bottom_margin(12)
        .build();
    readout.add_css_class("readout");

    let scroller = gtk4::ScrolledWindow::builder()
        .hexpand(true)
        .vexpand(true)
        .child(&readout)
        .build();
    scroller.add_css_class("readout-frame");

    let title = gtk4::Label::builder().xalign(0.0).label("Estado").build();
    title.add_css_class("panel-title");

    let status_dot = gtk4::Label::builder().label("● comprobando").build();

    // The badge is not decoration: it is the promise this window makes.
    let quiet = gtk4::Label::builder().label("NO NOTIFICATIONS").build();
    quiet.add_css_class("quiet-badge");
    quiet.set_tooltip_text(Some(
        "This window never raises a notification, a popup or a sound.\n\
         If somebody is reading over your shoulder, a machine that warns you on \
         screen gives you away. Alerts go to your phone and nowhere else.",
    ));

    let refresh = gtk4::Button::from_icon_name("view-refresh-symbolic");
    refresh.set_tooltip_text(Some("Reload this panel"));

    let header_left = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    header_left.append(&title);
    header_left.append(&status_dot);

    let header = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(10)
        .margin_start(14)
        .margin_end(14)
        .margin_top(10)
        .margin_bottom(6)
        .build();
    header.append(&header_left);
    let spacer = gtk4::Box::new(gtk4::Orientation::Horizontal, 0);
    spacer.set_hexpand(true);
    header.append(&spacer);
    header.append(&quiet);
    header.append(&refresh);

    // ── Ask it something ─────────────────────────────────────────────────────
    // The reason this window exists: so a question does not have to be typed
    // into a chat app in front of colleagues.
    let entry = gtk4::Entry::builder()
        .placeholder_text("Ask the machine…  (Enter to send)")
        .hexpand(true)
        .build();
    let send = gtk4::Button::from_icon_name("document-send-symbolic");
    send.set_tooltip_text(Some("Enviar"));

    let ask_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_start(14)
        .margin_end(14)
        .margin_top(8)
        .margin_bottom(12)
        .build();
    ask_row.append(&entry);
    ask_row.append(&send);

    let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    content.append(&header);
    content.append(&scroller);
    content.append(&ask_row);

    // ── Sidebar ──────────────────────────────────────────────────────────────
    let list = gtk4::ListBox::new();
    list.set_selection_mode(gtk4::SelectionMode::Single);
    list.add_css_class("navigation-sidebar");
    for p in PANELS {
        let row = adw::ActionRow::builder()
            .title(p.title)
            .subtitle(p.subtitle)
            .build();
        row.add_prefix(&gtk4::Image::from_icon_name(p.icon));
        row.set_widget_name(p.id);
        list.append(&row);
    }

    let sidebar_scroll = gtk4::ScrolledWindow::builder()
        .width_request(240)
        .child(&list)
        .build();

    let split = adw::OverlaySplitView::builder()
        .sidebar(&sidebar_scroll)
        .content(&content)
        .build();

    let toolbar = adw::ToolbarView::new();
    let bar = adw::HeaderBar::new();
    bar.set_title_widget(Some(&adw::WindowTitle::new(
        "sysentinel",
        "local console · quiet by design",
    )));
    toolbar.add_top_bar(&bar);
    toolbar.set_content(Some(&split));

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("sysentinel")
        .default_width(1080)
        .default_height(720)
        .content(&toolbar)
        .build();

    // ── Wiring ───────────────────────────────────────────────────────────────
    let current = std::rc::Rc::new(std::cell::Cell::new(0usize));

    let load = {
        let readout = readout.clone();
        let title = title.clone();
        let status_dot = status_dot.clone();
        let socket = socket.clone();
        move |index: usize| {
            let panel = PANELS[index].clone();
            title.set_text(panel.title);
            readout.buffer().set_text("loading…");

            // The request runs on a worker: probing every disk takes real time,
            // and a UI that freezes while it happens is worse than none.
            let (tx, rx) = async_channel::bounded::<Result<String, String>>(1);
            let socket = socket.clone();
            std::thread::spawn(move || {
                let result =
                    ipc::ask(&socket, panel.request.clone()).map_err(|e| e.to_string());
                let _ = tx.send_blocking(result);
            });

            let readout = readout.clone();
            let status_dot = status_dot.clone();
            glib::spawn_future_local(async move {
                match rx.recv().await {
                    Ok(Ok(text)) => {
                        readout.buffer().set_text(&text);
                        status_dot.set_text("● daemon online");
                        status_dot.remove_css_class("offline");
                        status_dot.add_css_class("online");
                    }
                    Ok(Err(message)) => {
                        readout.buffer().set_text(&message);
                        status_dot.set_text("● no daemon");
                        status_dot.remove_css_class("online");
                        status_dot.add_css_class("offline");
                    }
                    Err(_) => {
                        readout.buffer().set_text("the worker exited without answering");
                    }
                }
            });
        }
    };

    list.connect_row_selected({
        let load = load.clone();
        let current = current.clone();
        move |_, row| {
            if let Some(row) = row {
                let index = row.index().max(0) as usize;
                if index < PANELS.len() {
                    current.set(index);
                    load(index);
                }
            }
        }
    });

    // Asking runs on a worker like every other request: a model call takes
    // seconds, and the window must stay alive while it does.
    let ask = {
        let readout = readout.clone();
        let title = title.clone();
        let entry = entry.clone();
        let send = send.clone();
        let socket = socket.clone();
        move || {
            let question = entry.text().to_string();
            if question.trim().is_empty() {
                return;
            }
            entry.set_text("");
            entry.set_sensitive(false);
            send.set_sensitive(false);
            title.set_text("Conversation");
            readout
                .buffer()
                .set_text(&format!("> {question}\n\nthinking…"));

            let (tx, rx) = async_channel::bounded::<Result<String, String>>(1);
            let socket = socket.clone();
            let q = question.clone();
            std::thread::spawn(move || {
                let r = ipc::ask(&socket, ipc::Request::Chat { text: q })
                    .map_err(|e| e.to_string());
                let _ = tx.send_blocking(r);
            });

            let readout = readout.clone();
            let entry = entry.clone();
            let send = send.clone();
            glib::spawn_future_local(async move {
                let body = match rx.recv().await {
                    Ok(Ok(answer)) => answer,
                    Ok(Err(message)) => message,
                    Err(_) => "the worker exited without answering".to_string(),
                };
                readout
                    .buffer()
                    .set_text(&format!("> {question}\n\n{body}"));
                entry.set_sensitive(true);
                send.set_sensitive(true);
                entry.grab_focus();
            });
        }
    };

    entry.connect_activate({
        let ask = ask.clone();
        move |_| ask()
    });
    send.connect_clicked({
        let ask = ask.clone();
        move |_| ask()
    });

    refresh.connect_clicked({
        let load = load.clone();
        let current = current.clone();
        move |_| load(current.get())
    });

    // A slow heartbeat, so a panel left open does not go stale. Polling, never
    // pushing: the daemon is not allowed to interrupt this window either.
    glib::timeout_add_local(Duration::from_secs(30), {
        let load = load.clone();
        let current = current.clone();
        move || {
            load(current.get());
            glib::ControlFlow::Continue
        }
    });

    if let Some(first) = list.row_at_index(0) {
        list.select_row(Some(&first));
    }

    window.present();
}
