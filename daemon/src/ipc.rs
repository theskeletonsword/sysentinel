// SPDX-License-Identifier: Apache-2.0
//!
//! Local control socket — what the desktop GUI talks to.
//!
//! A Unix domain socket speaking line-delimited JSON. One request per line, one
//! response per line, no session state. It exists so a local front-end can show
//! everything the Telegram bot can show, without the owner having to type into a
//! chat window in front of colleagues.
//!
//! # It never notifies
//!
//! This socket answers questions. It does not push, it does not raise desktop
//! notifications, it does not ring, and it never volunteers anything the caller
//! did not ask for. That is a deliberate security property, not an omission.
//!
//! The reasoning is the same one behind [`crate::facenn::FaceScene`]: if someone
//! is standing over the owner, a machine that pops "🚨 UNKNOWN FACE DETECTED"
//! onto the screen has announced that it informed on them, and the owner is the
//! one who pays for it. Alerts therefore stay on the out-of-band channel, where
//! only the owner's phone sees them. The GUI is somewhere you go and look, on
//! purpose and in your own time. It is quiet by design.
//!
//! # Who can connect
//!
//! Whoever can open the socket file gets whatever the configured policy allows,
//! and the daemon runs as root — so the socket's mode and group *are* the
//! access control. It is created `0600` root-only unless `[ipc] group` names a
//! group to hand it to, in which case it becomes `0660` for that group.
//!
//! Destructive operations keep the ARM → `CONFIRM-XXXXXX` ritual they have in
//! the chat. A local front-end is a convenience; it is not a proof of identity,
//! and it does not get to skip the step that is.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// A request from the front-end. One JSON object per line.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness plus the daemon's identity.
    Ping,
    /// Everything a dashboard needs in one round trip.
    Status,
    /// PMU counters, per core type where the CPU is hybrid.
    Pmu,
    /// Ring −3 coprocessor detail.
    Ring3,
    /// The MEI/HECI client directory.
    Mei,
    /// Sensors present and the circumstances they cannot cover.
    Presence,
    /// Block devices with their identified on-disk format.
    Volumes,
    /// Which face engine is live and what is enrolled.
    Face,
    /// Ask the machine a question, in the configured persona.
    ///
    /// Read-only by construction: this path renders an answer and nothing
    /// else. Control orders keep the ARM → CONFIRM ritual on the out-of-band
    /// channel, because a window on an unlocked desktop proves nothing about
    /// who is sitting at it.
    Chat { text: String },
}

/// A response. `ok` carries a rendered, human-readable block; the front-end
/// decides how to present it rather than the daemon deciding for it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Ok { text: String },
    Error { message: String },
}

impl Response {
    fn ok(text: impl Into<String>) -> Self {
        Response::Ok { text: text.into() }
    }
    fn err(message: impl Into<String>) -> Self {
        Response::Error { message: message.into() }
    }
}

/// Default socket location.
pub fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/sysentinel/gui.sock")
}

/// Serve one request. Split from the transport so every operation is testable
/// without a socket.
pub fn handle(
    req: &Request,
    config: &crate::config::Config,
    settings: &Arc<Mutex<crate::settings::Settings>>,
    llm: &dyn crate::llm::LlmBackend,
) -> Response {
    match req {
        Request::Ping => Response::ok(format!(
            "sysentinel-daemon {} — quiet by design: this socket answers, it never notifies",
            env!("CARGO_PKG_VERSION")
        )),

        Request::Status => {
            let mut out = String::new();
            out.push_str(&crate::hwinfo::hardware_report());
            out.push('\n');
            out.push_str(&crate::pmu::quick_snapshot().to_context_string());
            Response::ok(out)
        }

        Request::Pmu => Response::ok(crate::pmu::quick_snapshot().to_context_string()),

        Request::Ring3 => Response::ok(crate::hal::hal_info().render_markdown()),

        Request::Mei => Response::ok(crate::meiclients::enumerate().render()),

        Request::Presence => {
            let base = crate::presence::default_baseline_path(&config.face.path);
            Response::ok(crate::presence::PresenceEvidence::collect(&base).render())
        }

        Request::Volumes => {
            let mut out = String::from("Volúmenes:\n");
            for b in crate::hwinfo::block_devices() {
                let kind = crate::fsprobe::probe_block(&b.name)
                    .map(|k| k.label().to_string())
                    .unwrap_or_else(|| "sin poder leer (¿permisos?)".to_string());
                out.push_str(&format!(
                    "  {:<12} {:>7} GB  {:<6}  {kind}\n",
                    b.name,
                    b.bytes / 1_000_000_000,
                    b.kind
                ));
            }
            Response::ok(out)
        }

        Request::Chat { text } => {
            if text.trim().is_empty() {
                return Response::err("pregunta vacía");
            }
            if !config.llm.llm_enabled() {
                return Response::err(
                    "el LLM está desactivado en config.toml — los paneles siguen \
                     funcionando, pero no hay con quién hablar",
                );
            }
            let persona = crate::llm::resolved_persona(config);
            let override_txt = {
                let g = settings.lock().expect("settings mutex");
                g.system_prompt_override.clone()
            };
            let system_prompt =
                crate::llm::effective_system_prompt(config, override_txt.as_deref());
            let directive = format!(
                "You ARE this machine, answering its owner at a local console. \
                 Answer in YOUR voice, in their language, naturally and briefly — \
                 no log formatting, no titles.\nlanguage: {}\ntone: {}\n\n{}",
                persona.language, persona.tone, text
            );
            match llm.explain(&crate::llm::ExplainRequest {
                system_prompt: &system_prompt,
                event_text: &directive,
                max_tokens: config.llm.max_tokens,
            }) {
                Ok(answer) => Response::ok(answer),
                Err(e) => Response::err(format!("el modelo no respondió: {e:#}")),
            }
        }

        Request::Face => {
            let engine = if crate::facenn::available(&config.face) {
                format!(
                    "red neuronal (coseno ≥ {:.2} dueño, ≥ {:.2} dudoso)",
                    config.face.nn_owner, config.face.nn_ambiguous
                )
            } else {
                format!("hash perceptual — falta {}", config.face.tool_path)
            };
            let enrolled = crate::fhash::FaceStore::load(Path::new(&config.face.path))
                .map(|s| s.len())
                .unwrap_or(0);
            let _ = settings; // reserved: live settings will surface here
            Response::ok(format!(
                "Motor: {engine}\nEnrolamientos: {enrolled}\nHabilitado: {}",
                config.face.enabled
            ))
        }
    }
}

/// Create the socket with the configured ownership, replacing any stale one.
///
/// A leftover socket from a killed daemon would otherwise make binding fail, so
/// it is removed — but only after checking it really is a socket, so a
/// misconfigured path cannot delete a regular file.
fn bind(path: &Path, group: Option<u32>) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(md) = std::fs::metadata(path) {
        if md.file_type().is_socket() {
            std::fs::remove_file(path)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket — refusing to remove it", path.display()),
            ));
        }
    }

    let listener = UnixListener::bind(path)?;

    // The socket's permissions ARE the access control: the daemon behind it is
    // root. Owner-only unless a group was named on purpose.
    let mode = if group.is_some() { 0o660 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    if let Some(gid) = group {
        // SAFETY: `path` is a valid NUL-terminated C string for the call, and
        // -1 leaves the owner unchanged.
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        unsafe {
            if libc::chown(c.as_ptr(), u32::MAX, gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(listener)
}

/// Resolve a group name to a gid.
fn gid_for(group: &str) -> Option<u32> {
    let c = std::ffi::CString::new(group).ok()?;
    // SAFETY: `c` is a valid C string; getgrnam returns a pointer into a static
    // buffer or NULL, and it is read before any other libc call can clobber it.
    unsafe {
        let g = libc::getgrnam(c.as_ptr());
        if g.is_null() {
            None
        } else {
            Some((*g).gr_gid)
        }
    }
}

/// Serve the control socket until the process ends.
pub fn run_ipc_loop(
    config: &crate::config::Config,
    settings: &Arc<Mutex<crate::settings::Settings>>,
    llm: &dyn crate::llm::LlmBackend,
) {
    let path = default_socket_path();
    let group = config.ipc.group.as_deref().and_then(|g| {
        let gid = gid_for(g);
        if gid.is_none() {
            log::warn!("ipc: group '{g}' does not exist — keeping the socket root-only");
        }
        gid
    });

    let listener = match bind(&path, group) {
        Ok(l) => l,
        Err(e) => {
            log::warn!("ipc: cannot listen on {}: {e} — no local GUI channel", path.display());
            return;
        }
    };
    log::info!(
        "ipc: listening on {} (mode {}) — answers only, never notifies",
        path.display(),
        if group.is_some() { "0660" } else { "0600" }
    );

    for stream in listener.incoming() {
        match stream {
            Ok(s) => serve_connection(s, config, settings, llm),
            Err(e) => log::warn!("ipc: accept failed: {e}"),
        }
    }
}

/// One connection: read requests line by line until the peer goes away.
fn serve_connection(
    stream: UnixStream,
    config: &crate::config::Config,
    settings: &Arc<Mutex<crate::settings::Settings>>,
    llm: &dyn crate::llm::LlmBackend,
) {
    log::debug!("ipc: client connected");
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    let reader = BufReader::new(stream);
    let mut writer = write_half;

    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle(&req, config, settings, llm),
            Err(e) => Response::err(format!("request no reconocida: {e}")),
        };
        let Ok(mut encoded) = serde_json::to_string(&response) else {
            break;
        };
        encoded.push('\n');
        if writer.write_all(encoded.as_bytes()).is_err() {
            break;
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_as_tagged_json() {
        // The wire format is the contract with the GUI; pin it.
        let cases = [
            (Request::Ping, r#"{"op":"ping"}"#),
            (Request::Status, r#"{"op":"status"}"#),
            (Request::Pmu, r#"{"op":"pmu"}"#),
            (Request::Volumes, r#"{"op":"volumes"}"#),
        ];
        for (req, json) in cases {
            assert_eq!(serde_json::to_string(&req).unwrap(), json);
            assert_eq!(serde_json::from_str::<Request>(json).unwrap(), req);
        }
    }

    #[test]
    fn an_unknown_request_is_an_error_not_a_panic() {
        assert!(serde_json::from_str::<Request>(r#"{"op":"rm_rf"}"#).is_err());
        assert!(serde_json::from_str::<Request>("not json").is_err());
    }

    #[test]
    fn bind_refuses_to_delete_something_that_is_not_a_socket() {
        // A mistyped path must never cost the owner a file.
        let dir = std::env::temp_dir().join(format!("sysentinel-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("important.txt");
        std::fs::write(&victim, b"do not delete me").unwrap();

        let err = bind(&victim, None).expect_err("must refuse a regular file");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "do not delete me");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_socket_is_replaced_and_is_owner_only() {
        let dir = std::env::temp_dir().join(format!("sysentinel-ipc-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gui.sock");

        let first = bind(&path, None).expect("first bind");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the daemon behind this socket is root");
        drop(first);

        // A killed daemon leaves the socket file behind; rebinding must work.
        bind(&path, None).expect("rebind over a stale socket");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_real_client_gets_a_real_answer_over_the_socket() {
        use std::io::{BufRead, BufReader, Write};
        let dir = std::env::temp_dir().join(format!("sysentinel-ipc-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gui.sock");
        let listener = bind(&path, None).expect("bind");

        let cfg: crate::config::Config = toml::from_str(
            r#"
            [general]
            [persona]
            tone = "casual"
            emotions = true
            language = "Spanish"
            [telegram]
            bot_token = "t"
            [llm]
            model = "m"
            "#,
        )
        .expect("config parses");
        let settings = Arc::new(Mutex::new(crate::settings::Settings::default()));
        let server = std::thread::spawn(move || {
            if let Ok((s, _)) = listener.accept() {
                let llm = crate::llm::NoneBackend;
                serve_connection(s, &cfg, &settings, &llm);
            }
        });

        let mut client = UnixStream::connect(&path).expect("connect");
        client.write_all(b"{\"op\":\"ping\"}\n").unwrap();
        client.write_all(b"garbage\n").unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());

        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let r: Response = serde_json::from_str(&line).unwrap();
        match r {
            Response::Ok { text } => {
                assert!(text.contains("never notifies"), "{text}");
            }
            Response::Error { message } => panic!("ping failed: {message}"),
        }

        // A malformed line must be answered, not close the connection.
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert!(matches!(
            serde_json::from_str::<Response>(&line).unwrap(),
            Response::Error { .. }
        ));

        drop(reader);
        drop(client);
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_nonexistent_group_does_not_widen_access() {
        assert!(gid_for("definitely-not-a-real-group-xyzzy").is_none());
        // root always exists, and resolves to 0.
        assert_eq!(gid_for("root"), Some(0));
    }
}
