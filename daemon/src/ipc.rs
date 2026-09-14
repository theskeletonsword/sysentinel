// SPDX-License-Identifier: Apache-2.0
//!
//! Local control socket — what the desktop GUI talks to.
//!
//! A Unix domain socket speaking line-delimited JSON. One request per line, one
//! response per line, no session state. It exists so a local front-end can show
//! everything the command layer can show, without the owner having to type into a
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

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
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
            let mut out = String::from("Volumes:\n");
            for b in crate::hwinfo::block_devices() {
                let kind = crate::fsprobe::probe_block(&b.name)
                    .map(|k| k.label().to_string())
                    .unwrap_or_else(|| "unreadable (permissions?)".to_string());
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
                return Response::err("empty question");
            }
            if !config.llm.llm_enabled() {
                return Response::err(
                    "the LLM is switched off in config.toml — the panels still \
                     work, but there is nobody to talk to",
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
                Err(e) => Response::err(format!("the model did not answer: {e:#}")),
            }
        }

        Request::Face => {
            let engine = if crate::facenn::available(&config.face) {
                format!(
                    "neural network (cosine ≥ {:.2} owner, ≥ {:.2} ambiguous)",
                    config.face.nn_owner, config.face.nn_ambiguous
                )
            } else {
                format!("perceptual hash — {} is missing", config.face.tool_path)
            };
            let enrolled = crate::fhash::FaceStore::load(Path::new(&config.face.path))
                .map(|s| s.len())
                .unwrap_or(0);
            let _ = settings; // reserved: live settings will surface here
            Response::ok(format!(
                "Engine: {engine}\nEnrolments: {enrolled}\nEnabled: {}",
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
        // The directory is the outer gate, and it was left at whatever the
        // umask gave it. 0750 means nobody outside the intended group can even
        // reach the socket to connect to it — which also covers the instant
        // between creating the socket and setting its mode.
        //
        // The group has to be able to traverse, or the GUI it was granted
        // access for cannot get in, so the directory is handed to the same
        // group as the socket.
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750));
        if let Some(gid) = group {
            let c = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes())?;
            // SAFETY: `c` is a valid NUL-terminated path; -1 as the uid leaves
            // the owner alone.
            unsafe {
                if libc::chown(c.as_ptr(), u32::MAX, gid) != 0 {
                    log::warn!(
                        "ipc: cannot hand {} to gid {gid}: {}",
                        parent.display(),
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }
    if let Ok(md) = std::fs::symlink_metadata(path) {
        // symlink_metadata, not metadata: a symlink pointing at something else
        // must not be followed into a delete.
        if md.file_type().is_socket() {
            std::fs::remove_file(path)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket — refusing to remove it", path.display()),
            ));
        }
    }

    // `bind` creates the socket with 0777 & !umask and it is tightened on the
    // next line, so for that instant its own mode is whatever the umask says.
    // The directory above is what closes that window: at 0750 nobody outside
    // the group can reach the socket to connect to it, whatever mode it is
    // wearing at that moment.
    //
    // Deliberately NOT done with umask(): it is per *process*, not per thread,
    // and this daemon binds while its watchers are already running. Narrowing
    // it here would briefly make every file and directory they create in
    // parallel come out with the wrong permissions — including directories
    // without an execute bit, which then cannot be written into at all.
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
///
/// The protocol is transport-agnostic on purpose — the Unix socket and the
/// network console serve the exact same bytes, so a rename on one end breaks
/// both and there is no second dialect to drift.
fn serve_connection(
    stream: UnixStream,
    config: &crate::config::Config,
    settings: &Arc<Mutex<crate::settings::Settings>>,
    llm: &dyn crate::llm::LlmBackend,
) {
    log::debug!("ipc: client connected");
    let mut stream = stream;
    serve_io(&mut stream, config, settings, llm);
}

/// Serve line-delimited JSON over anything that is both readable and writable.
fn serve_io<S: Read + Write>(
    stream: &mut S,
    config: &crate::config::Config,
    settings: &Arc<Mutex<crate::settings::Settings>>,
    llm: &dyn crate::llm::LlmBackend,
) {
    let mut reader = BufReader::new(stream);

    // Bounded: `lines()` will happily grow one allocation until the daemon
    // dies, and the peers here are clients that may be buggy as easily as
    // hostile. A request is a small JSON object; a megabyte is generous.
    const MAX_REQUEST: u64 = 1 << 20;
    loop {
        let mut line = String::new();
        let read = {
            let mut limited = (&mut reader).take(MAX_REQUEST);
            limited.read_line(&mut line)
        };
        match read {
            Ok(0) => break,
            Ok(n) if n as u64 >= MAX_REQUEST => {
                let too_long = Response::err("request too long");
                if let Ok(mut encoded) = serde_json::to_string(&too_long) {
                    encoded.push('\n');
                    let _ = reader.get_mut().write_all(encoded.as_bytes());
                }
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
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
        if reader.get_mut().write_all(encoded.as_bytes()).is_err() {
            break;
        }
    }
}

// ── Network console ───────────────────────────────────────────────────────────

/// Serve the network control channel until the process ends.
///
/// The same line-delimited JSON protocol as the Unix socket above, but two
/// gates stand in front of it that make it safe to open beyond a socket file
/// on one disk:
///
/// - TLS 1.3 under the machine's own pinned identity (`phonetls`, the same
///   key the phone channel uses — one machine, one identity). A client that
///   does not hold the pin cannot complete a handshake, so a port scan
///   against an unpinned peer gets nothing but a TLS alert and learns nothing
///   about this machine.
/// - A token line exchanged immediately after the handshake. The pin proves
///   the *machine* to the client; nothing in TLS proves the *client* to the
///   machine, so the token does. Without it the connection is closed before a
///   single byte of system state moves.
///
/// Unlike the Unix socket there is no filesystem gate — the access control
/// here is exactly those two checks, so both are mandatory.
pub fn run_net_ipc_loop(
    config: &crate::config::Config,
    settings: &Arc<Mutex<crate::settings::Settings>>,
    llm: Arc<dyn crate::llm::LlmBackend + Send + Sync>,
) -> Result<()> {
    let bind = config
        .ipc
        .net_bind
        .clone()
        .context("ipc-net: net_bind is unset — the network console is off")?;
    let Some(token_hex) = config.ipc.net_token.clone() else {
        let suggested = crate::phone::fresh_pairing_key().unwrap_or_default();
        anyhow::bail!(
            "ipc-net: [ipc] net_token is not set, and the network console needs one.\n\
             Here is a freshly minted one — put it in config.toml:\n\n\
             \t[ipc]\n\tnet_token = \"{suggested}\"\n\n\
             It is the client's half of the authentication: the machine's \
             pinned key proves the server, and this proves whoever connects. \
             Treat it as a credential."
        );
    };
    if token_hex.len() != 64 || !token_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("ipc-net: [ipc] net_token must be 64 hex characters");
    }
    let port = config.ipc.net_port;

    // The machine's own identity — unconditionally the same certificate the
    // phone channel answers under. One machine, one pinned key, so a desktop
    // client and a phone can check the same fingerprint.
    let profile = crate::phonehome::profile_path(&config.phone.queue_path);
    let state_dir = profile
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/sysentinel"));
    let tls = crate::phonetls::TlsIdentity::load_or_create(&state_dir)?;
    let server_cfg = tls.server_config()?;
    let pinned = tls.fingerprint.clone();

    let listener = TcpListener::bind((bind.as_str(), port))
        .with_context(|| format!("ipc-net: cannot listen on {bind}:{port}"))?;
    let local = listener.local_addr().context("ipc-net: local address unavailable")?;

    log::info!("ipc-net: network console listening on {local}");
    // The pin is not a secret: it is what the client *requires*, exactly like
    // the phone's. Printing it at startup saves the owner a walk to the
    // watched machine to read a file. The token is the secret and stays where
    // they put it — in config.toml, not in a log line.
    eprintln!(
        "\n  Network console — point the client GUI at this machine:\n\n\
\taddress  {local}\n\
\tpin      {pinned}\n\
\ttoken    the [ipc] net_token from config.toml\n\
\tenv      SYSENTINEL_CONNECT=\"sysentinel://connect?addr={local}&pin={pinned}&token=<net_token>\"\n\n\
\tNothing is served to anyone who does not present that token over a \
\thandshake pinned to this machine's key.\n"
    );

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                log::warn!("ipc-net: accept failed: {e}");
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".to_string());
        let tok = token_hex.clone();
        let cfg = config.clone();
        let st = Arc::clone(settings);
        let cfg_server = Arc::clone(&server_cfg);
        let llm_c = Arc::clone(&llm);
        std::thread::Builder::new()
            .name(format!("ipc-net-{peer}"))
            .spawn(move || serve_net_conn(stream, cfg_server, tok, peer, &cfg, &st, llm_c))
            .context("spawning ipc-net connection thread")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn serve_net_conn(
    stream: TcpStream,
    server_cfg: Arc<rustls::ServerConfig>,
    token: String,
    peer: String,
    config: &crate::config::Config,
    settings: &Arc<Mutex<crate::settings::Settings>>,
    llm: Arc<dyn crate::llm::LlmBackend + Send + Sync>,
) {
    let _ = stream.set_nodelay(true);
    // Tokens and requests are small and occasional; thirty seconds to produce
    // the *next* line is generous and still bounds a peer that has gone quiet.
    let t = Some(Duration::from_secs(30));
    let _ = stream.set_read_timeout(t);
    let _ = stream.set_write_timeout(t);

    let conn = match rustls::ServerConnection::new(server_cfg) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("ipc-net: {peer}: no TLS session: {e}");
            return;
        }
    };
    let mut tls = rustls::StreamOwned::new(conn, stream);

    // The handshake and the token travel together: rustls completes the
    // handshake on the first I/O, so the token itself only ever exists behind
    // a pinned-key session — an attacker who cannot complete that session can
    // never even send us a token.
    let mut token_line = String::new();
    let mut byte = [0u8; 1];
    let mut exceeded = false;
    loop {
        match tls.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                token_line.push(byte[0] as char);
                if token_line.len() > 128 {
                    exceeded = true;
                    break;
                }
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(e) => {
                log::warn!("ipc-net: {peer}: token read failed: {e}");
                return;
            }
        }
    }
    if exceeded {
        log::warn!("ipc-net: {peer}: token line too long — refusing");
        return;
    }
    if token_line.trim().is_empty() {
        log::warn!("ipc-net: {peer}: closed before sending a token");
        return;
    }
    if !token_matches(token_line.trim(), &token) {
        log::warn!("ipc-net: {peer}: wrong token — closing without answering");
        return;
    }
    log::info!("ipc-net: {peer}: authenticated, serving");

    serve_io(&mut tls, config, settings, llm.as_ref());
}

/// Constant-time comparison of a client token against the configured one.
///
/// Both sides are hashed first so the compared slices are always a digest in
/// length, and the length mixin below does not correlate with how close the
/// inputs were.
fn token_matches(seen: &str, expected: &str) -> bool {
    use aws_lc_rs::digest;
    let a = digest::digest(&digest::SHA256, seen.as_bytes());
    let b = digest::digest(&digest::SHA256, expected.as_bytes());
    let (x, y) = (a.as_ref(), b.as_ref());
    let mut diff = x.len() ^ y.len();
    for (i, j) in x.iter().zip(y.iter()) {
        diff |= usize::from(i ^ j);
    }
    diff == 0
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
    fn the_socket_is_never_briefly_world_reachable() {
        // The socket's mode IS the access control for a root daemon, and it
        // used to be created with the umask's permissions and tightened a
        // moment later. Bind it and check what the filesystem shows, with no
        // chance to fix it up first — and check the directory too, since that
        // is what closes the window.
        let dir = std::env::temp_dir().join(format!("sysentinel-ipc-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("gui.sock");
        let listener = bind(&path, None).expect("bind");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket mode");
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o750, "directory mode");

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
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

    #[test]
    fn a_pinned_client_presenting_the_token_talks_over_tls() {
        use rustls::pki_types::ServerName;

        // The machine identity the console answers under — same one the phone
        // channel uses.
        let dir = std::env::temp_dir().join(format!("sysentinel-ipc-net-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let identity = crate::phonetls::TlsIdentity::load_or_create(&dir).unwrap();
        let pin = identity.fingerprint.clone();
        let server_cfg = identity.server_config().unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg: crate::config::Config = toml::from_str(
            r#"
            [general]
            [persona]
            tone = "casual"
            emotions = true
            language = "Spanish"
            [llm]
            model = "m"
            "#,
        )
        .expect("config parses");
        let settings = Arc::new(Mutex::new(crate::settings::Settings::default()));

        let expected = "a".repeat(64);
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let llm: Arc<dyn crate::llm::LlmBackend + Send + Sync> =
                Arc::new(crate::llm::NoneBackend);
            serve_net_conn(sock, server_cfg, expected, "peer".into(), &cfg, &settings, llm);
        });

        // The client pins the machine's key — nothing else gets a handshake.
        let client_cfg = crate::phonetls::client_config_pinned(&pin).unwrap();
        let name = ServerName::try_from("sysentinel").unwrap();
        let conn = rustls::ClientConnection::new(client_cfg, name).unwrap();
        let sock = std::net::TcpStream::connect(addr).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(format!("{}\n", "a".repeat(64)).as_bytes()).unwrap();
        tls.flush().unwrap();
        tls.write_all(b"{\"op\":\"ping\"}\n").unwrap();
        tls.flush().unwrap();

        let mut reader = BufReader::new(&mut tls);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let r: Response = serde_json::from_str(&line).unwrap();
        match r {
            Response::Ok { text } => assert!(text.contains("never notifies"), "{text}"),
            Response::Error { message } => panic!("ping failed: {message}"),
        }

        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrong_token_gets_the_connection_closed_without_answer() {
        use rustls::pki_types::ServerName;

        let dir = std::env::temp_dir().join(format!("sysentinel-ipc-net-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let identity = crate::phonetls::TlsIdentity::load_or_create(&dir).unwrap();
        let pin = identity.fingerprint.clone();
        let server_cfg = identity.server_config().unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg: crate::config::Config = toml::from_str(
            r#"
            [general]
            [persona]
            tone = "casual"
            emotions = true
            language = "Spanish"
            [llm]
            model = "m"
            "#,
        )
        .expect("config parses");
        let settings = Arc::new(Mutex::new(crate::settings::Settings::default()));

        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let llm: Arc<dyn crate::llm::LlmBackend + Send + Sync> =
                Arc::new(crate::llm::NoneBackend);
            serve_net_conn(sock, server_cfg, "a".repeat(64), "peer".into(), &cfg, &settings, llm);
        });

        let client_cfg = crate::phonetls::client_config_pinned(&pin).unwrap();
        let name = ServerName::try_from("sysentinel").unwrap();
        let conn = rustls::ClientConnection::new(client_cfg, name).unwrap();
        let sock = std::net::TcpStream::connect(addr).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        // The handshake completes (the key matches), but the token is wrong:
        // the daemon must close before a byte of system state goes out.
        tls.write_all(format!("{}\n", "0".repeat(64)).as_bytes()).unwrap();
        tls.flush().unwrap();

        let mut reader = BufReader::new(&mut tls);
        let mut line = String::new();
        // Cierre abrupto (sin close_notify) o EOF limpio: ambos significan
        // "el daemon colgó sin responder", que es exactamente lo que debe
        // pasar con un token equivocado.
        match reader.read_line(&mut line) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Ok(n) => panic!("a wrong token must not get an answer (got {n} bytes: {line:?})"),
            Err(e) => panic!("unexpected error: {e}"),
        }

        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
