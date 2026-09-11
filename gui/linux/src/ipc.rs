// SPDX-License-Identifier: Apache-2.0
//!
//! Client for the daemon's local control socket.
//!
//! Line-delimited JSON over a Unix socket. The wire format is defined by
//! `daemon/src/ipc.rs`; these types mirror it and the round-trip is pinned by a
//! test on both sides, so a rename on one end fails loudly rather than silently
//! producing "request no reconocida".
//!
//! Every call here **blocks**, on purpose. It is not called from the UI thread:
//! see `main.rs`, where requests run on a worker and results come back through
//! a channel. A GUI that freezes while a disk is probed is worse than no GUI.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Requests the daemon answers. Mirrors `daemon::ipc::Request`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Status,
    Pmu,
    Ring3,
    Mei,
    Presence,
    Volumes,
    Face,
    /// Ask the machine something, answered in its configured persona.
    Chat { text: String },
}

/// Mirrors `daemon::ipc::Response`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Ok { text: String },
    Error { message: String },
}

/// Where the daemon listens unless told otherwise.
pub fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/sysentinel/gui.sock")
}

/// Why a request could not be answered, in words a person can act on.
#[derive(Debug)]
pub enum IpcError {
    /// The socket file is not there at all.
    NotListening(PathBuf),
    /// It exists but we were not allowed to open it.
    Forbidden(PathBuf),
    /// Anything else at the transport level.
    Io(std::io::Error),
    /// The daemon answered something this client could not read.
    Protocol(String),
    /// The daemon answered, with an error of its own.
    Daemon(String),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcError::NotListening(p) => write!(
                f,
                "The daemon is not listening on {}.\n\n\
                 The socket is off by default. Switch it on in config.toml:\n\n\
                 \t[ipc]\n\tenabled = true\n\n\
                 …y reinicia el daemon.",
                p.display()
            ),
            IpcError::Forbidden(p) => write!(
                f,
                "No permission to open {}.\n\n\
                 The socket is root-only 0600 unless you name a group. Add your \
                 usuario a ese grupo y ponlo en config.toml:\n\n\
                 \t[ipc]\n\tenabled = true\n\tgroup = \"sysentinel\"\n\n\
                 The daemon behind the socket runs as root, so those \
                 permisos SON el control de acceso.",
                p.display()
            ),
            IpcError::Io(e) => write!(f, "I/O error talking to the daemon: {e}"),
            IpcError::Protocol(m) => write!(f, "An answer I do not understand: {m}"),
            IpcError::Daemon(m) => write!(f, "The daemon returned an error: {m}"),
        }
    }
}

/// Send one request and read one answer.
///
/// A fresh connection per request: the protocol is stateless, requests are
/// occasional, and a connection held open across a daemon restart is a source
/// of confusing failures for no gain.
pub fn ask(socket: &Path, req: Request) -> Result<String, IpcError> {
    let stream = UnixStream::connect(socket).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => IpcError::NotListening(socket.to_path_buf()),
        std::io::ErrorKind::PermissionDenied => IpcError::Forbidden(socket.to_path_buf()),
        _ => IpcError::Io(e),
    })?;

    // A daemon that accepts and then stalls must not hang the worker forever.
    let t = Some(Duration::from_secs(20));
    stream.set_read_timeout(t).map_err(IpcError::Io)?;
    stream.set_write_timeout(t).map_err(IpcError::Io)?;

    let mut writer = stream.try_clone().map_err(IpcError::Io)?;
    let mut line = serde_json::to_string(&req)
        .map_err(|e| IpcError::Protocol(e.to_string()))?;
    line.push('\n');
    writer.write_all(line.as_bytes()).map_err(IpcError::Io)?;
    writer.flush().map_err(IpcError::Io)?;

    let mut reader = BufReader::new(stream);
    let mut answer = String::new();
    let n = reader.read_line(&mut answer).map_err(IpcError::Io)?;
    if n == 0 {
        return Err(IpcError::Protocol(
            "the daemon closed the connection without answering".to_string(),
        ));
    }

    match serde_json::from_str::<Response>(&answer) {
        Ok(Response::Ok { text }) => Ok(text),
        Ok(Response::Error { message }) => Err(IpcError::Daemon(message)),
        Err(e) => Err(IpcError::Protocol(format!("{e}: {}", answer.trim()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_format_matches_the_daemon() {
        // Pinned on both sides. If either end renames a variant, one of these
        // fails instead of the user seeing "request no reconocida".
        assert_eq!(serde_json::to_string(&Request::Ping).unwrap(), r#"{"op":"ping"}"#);
        assert_eq!(serde_json::to_string(&Request::Ring3).unwrap(), r#"{"op":"ring3"}"#);
        assert_eq!(serde_json::to_string(&Request::Volumes).unwrap(), r#"{"op":"volumes"}"#);
        assert_eq!(
            serde_json::to_string(&Request::Chat { text: "hola".into() }).unwrap(),
            r#"{"op":"chat","text":"hola"}"#
        );
        let r: Response = serde_json::from_str(r#"{"ok":{"text":"hola"}}"#).unwrap();
        assert!(matches!(r, Response::Ok { text } if text == "hola"));
        let r: Response = serde_json::from_str(r#"{"error":{"message":"no"}}"#).unwrap();
        assert!(matches!(r, Response::Error { message } if message == "no"));
    }

    #[test]
    fn a_missing_socket_explains_how_to_turn_it_on() {
        // The likeliest failure by far, so it must not read as a crash.
        let err = ask(Path::new("/nonexistent/sysentinel.sock"), Request::Ping)
            .expect_err("must fail");
        let msg = err.to_string();
        assert!(matches!(err, IpcError::NotListening(_)));
        assert!(msg.contains("[ipc]"), "{msg}");
        assert!(msg.contains("enabled = true"), "{msg}");
    }
}
