// SPDX-License-Identifier: Apache-2.0
//!
//! Client for the daemon's network console.
//!
//! # What is this
//!
//! The daemon can serve its control protocol over TCP as well as the local
//! Unix socket: TLS 1.3 in front of the same line-delimited JSON, plus a token
//! exchanged right after the handshake. This module is the client half — the
//! "client GUI" that watches a machine from somewhere else (another room, or
//! another OS entirely).
//!
//! # The two authentication halves
//!
//! - **pin** — TLS 1.3 with the machine's certificate pinned. No CA, no name
//!   check: the machine signs on a LAN/VPN address nobody will ever certify,
//!   so the key IS the identity (exactly the phone channel's reasoning). A
//!   client that does not already hold the pin cannot even complete a
//!   handshake, so nothing about this machine leaks to a scanner.
//! - **token** — after the handshake the daemon demands a secret line before a
//!   single byte of system state moves. The pin proves the *machine* to us;
//!   the token proves *us* to the machine.
//!
//! The whole connection is one string the daemon prints at start:
//!
//! ```text
//! sysentinel://connect?addr=HOST:PORT&pin=sha256/…&token=<64 hex>
//! ```
//!
//! Point `SYSENTINEL_CONNECT` at it and run the GUI in client mode.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};

use crate::ipc::{Request, Response};

/// One console this GUI can watch: the machine's own socket, or a remote one.
///
/// Which of the two is a property of how it is launched, not of this process:
/// the daemon on the other end is the same programs, the protocol is the same
/// bytes, only the transport and its authentication differ.
#[derive(Debug, Clone)]
pub enum Target {
    /// Server GUI — talks to the local daemon over its Unix socket.
    Local(PathBuf),
    /// Client GUI — talks to a machine's network console over pinned TLS.
    Remote(Remote),
}

impl Target {
    /// How the connection should be labelled in the window header.
    pub fn describe(&self) -> String {
        match self {
            Target::Local(_) => "local console · quiet by design".to_string(),
            Target::Remote(r) => format!("client → {}:{}", r.host, r.port),
        }
    }

    /// Send one request and read one answer, over whichever transport.
    pub fn ask(&self, req: Request) -> Result<String, String> {
        match self {
            Target::Local(socket) => crate::ipc::ask(socket, req).map_err(|e| e.to_string()),
            Target::Remote(r) => ask_remote(r, req).map_err(|e| e.to_string()),
        }
    }
}

/// A remote console, fully described so it can be serialized and reused.
#[derive(Debug, Clone)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    /// `sha256/…` SPKI pin of the machine's certificate.
    pub pin: String,
    /// 64-hex secret that authenticates this client to the daemon.
    pub token: String,
}

/// Why a remote request could not be answered, in words a person can act on.
#[derive(Debug)]
pub enum RemoteError {
    /// Could not reach the address at all.
    Connect(std::io::Error),
    /// The machine answered the handshake but then closed without answering —
    /// the pin's wrong half of the pair or the token's.
    Rejected,
    /// TLS would not come up.
    Tls(String),
    /// The daemon sent a line this client could not read.
    Protocol(String),
    /// The daemon answered, with an error of its own.
    Daemon(String),
    /// The connect string itself is malformed.
    Config(String),
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteError::Connect(e) => write!(f, "No pudimos llegar por red: {e}"),
            RemoteError::Rejected => write!(
                f,
                "The daemon closed the connection instead of answering.\n\n\
                 With TLS 1.3 that means one of the two proofs failed:\n\n\
                 \tpin   — this client only accepts the machine whose key it \
                 was given;\n\
                 \ttoken — the daemon only answers a client that presents the \
                 right one.\n\n\
                 Revise el SYSENTINEL_CONNECT que le pasaste al GUI."
            ),
            RemoteError::Tls(m) => write!(f, "El TLS no arrancó: {m}"),
            RemoteError::Protocol(m) => write!(f, "Una respuesta que no entiendo: {m}"),
            RemoteError::Daemon(m) => write!(f, "El daemon devolvió un error: {m}"),
            RemoteError::Config(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for RemoteError {}

/// Parse a connect string printed by the daemon.
///
/// ```text
/// sysentinel://connect?addr=HOST:PORT&pin=sha256/…&token=<64 hex>
/// ```
pub fn parse_connect(uri: &str) -> Result<Remote, RemoteError> {
    if !uri.starts_with("sysentinel://connect?") {
        return Err(RemoteError::Config(format!(
            "Era de esperar 'sysentinel://connect?addr=…&pin=…&token=…' pero \
             me llegó: {uri}"
        )));
    }
    let mut addr: Option<&str> = None;
    let mut pin: Option<&str> = None;
    let mut token: Option<&str> = None;
    for pair in uri.trim_start_matches("sysentinel://connect?").split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        match k {
            "addr" => addr = Some(v),
            "pin" => pin = Some(v),
            "token" => token = Some(v),
            _ => {}
        }
    }
    let addr = addr.ok_or_else(|| RemoteError::Config("connect: falta addr=HOST:PORT".into()))?;
    let pin = pin.ok_or_else(|| RemoteError::Config("connect: falta pin=sha256/…".into()))?;
    let token = token.ok_or_else(|| RemoteError::Config("connect: falta token=<64 hex>".into()))?;

    if !pin.starts_with("sha256/") || pin.len() <= "sha256/".len() {
        return Err(RemoteError::Config("connect: el pin debe ser sha256/<base64>".into()));
    }
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RemoteError::Config(
            "connect: el token debe tener 64 caracteres hexadecimales".into(),
        ));
    }

    // The host may itself contain a colon ('[::1]:8888'); split at the last one.
    let Some((host, port_str)) = addr.rsplit_once(':') else {
        return Err(RemoteError::Config(format!(
            "connect: addr debe ser HOST:PORT, no '{addr}'"
        )));
    };
    if host.is_empty() || host.contains("://") {
        return Err(RemoteError::Config(format!(
            "connect: addr debe ser HOST:PORT, no '{addr}'"
        )));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|e| RemoteError::Config(format!("connect: puerto inválido '{port_str}': {e}")))?;

    Ok(Remote {
        host: host.to_string(),
        port,
        pin: pin.to_string(),
        token: token.to_string(),
    })
}

/// Send one request to a remote console and read one answer.
///
/// A fresh connection per request, like the local `ipc::ask`: the protocol is
/// stateless and a connection held open across a daemon restart is a source of
/// confusing failures. Every call blocks here — the caller runs it on a worker,
/// never on the UI thread.
pub fn ask_remote(remote: &Remote, req: Request) -> Result<String, RemoteError> {
    let sock = TcpStream::connect((remote.host.as_str(), remote.port))
        .map_err(RemoteError::Connect)?;
    let t = Some(Duration::from_secs(20));
    sock.set_read_timeout(t).map_err(RemoteError::Connect)?;
    sock.set_write_timeout(t).map_err(RemoteError::Connect)?;

    // Same crypto backend as the daemon: one implementation in the whole repo.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let verifier = Arc::new(PinnedServerVerifier::new(remote.pin.clone()));
    let mut cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
    cfg.enable_sni = false; // the pin is the identity; no name, no SNI to leak

    let name = ServerName::try_from("sysentinel")
        .map_err(|e| RemoteError::Tls(format!("nombre de servidor: {e}")))?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), name)
        .map_err(|e| RemoteError::Tls(e.to_string()))?;
    let mut tls = rustls::StreamOwned::new(conn, sock);

    // The token first, and it only ever exists behind the pinned handshake —
    // rustls completes the handshake on the first write, so the secret is
    // already private and forward-secret before it leaves this process.
    let mut line = format!("{}\n", remote.token);
    tls.write_all(line.as_bytes()).map_err(RemoteError::Connect)?;
    tls.flush().map_err(RemoteError::Connect)?;

    line = serde_json::to_string(&req).map_err(|e| RemoteError::Protocol(e.to_string()))?;
    line.push('\n');
    tls.write_all(line.as_bytes()).map_err(RemoteError::Connect)?;
    tls.flush().map_err(RemoteError::Connect)?;

    let mut reader = BufReader::new(&mut tls);
    let mut answer = String::new();
    match reader.read_line(&mut answer) {
        // A peer that closes with the response already delivered (no trailing
        // newline, or no close_notify) must not cost us the answer.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && answer.trim().is_empty() => {
            return Err(RemoteError::Rejected);
        }
        Ok(0) => return Err(RemoteError::Rejected),
        Ok(_) => {}
        Err(e) => return Err(RemoteError::Protocol(format!("lectura: {e}"))),
    }

    match serde_json::from_str::<Response>(&answer) {
        Ok(Response::Ok { text }) => Ok(text),
        Ok(Response::Error { message }) => Err(RemoteError::Daemon(message)),
        Err(e) => Err(RemoteError::Protocol(format!("{e}: {}", answer.trim()))),
    }
}

// ── Pinned verification ───────────────────────────────────────────────────────
//
// Accepts exactly one public key and refuses everything else. Ported from the
// daemon's `phonetls` (same rule, same bytes), so a rename or a drift on one
// side surfaces as a failed handshake, never as silently trusting something.

/// Accepts exactly one `sha256/…` pin and refuses every other key.
#[derive(Debug)]
struct PinnedServerVerifier {
    pin: String,
}

impl PinnedServerVerifier {
    fn new(pin: impl Into<String>) -> Self {
        PinnedServerVerifier { pin: pin.into() }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match spki_pin(end_entity) {
            Some(seen) if seen == self.pin => {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            _ => Err(rustls::Error::General("pin mismatch".into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// `sha256/<base64>` over the certificate's SubjectPublicKeyInfo — the pin the
/// daemon prints and this client requires.
fn spki_pin(cert: &CertificateDer<'_>) -> Option<String> {
    use aws_lc_rs::digest;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let spki = extract_spki(cert.as_ref())?;
    let sum = digest::digest(&digest::SHA256, spki);
    Some(format!("sha256/{}", STANDARD.encode(sum.as_ref())))
}

/// Walk a DER certificate to its SubjectPublicKeyInfo.
///
/// A Certificate is `SEQUENCE { tbsCertificate, signatureAlgorithm, signature }`
/// and the SPKI is the seventh field of tbsCertificate — after the optional
/// version tag, serial, signature, issuer, validity and subject. Counting them
/// is enough; nothing here needs to understand what they contain. Same walk as
/// the daemon's `httpsec::extract_spki`.
fn extract_spki(der: &[u8]) -> Option<&[u8]> {
    let (tbs, _) = der_sequence(der)?;
    let mut rest = tbs;
    // An explicit [0] version tag is optional; skip it if present.
    if rest.first()? & 0xA0 == 0xA0 {
        let (_, after) = der_element(rest)?;
        rest = after;
    }
    // serial, signature, issuer, validity, subject.
    for _ in 0..5 {
        let (_, after) = der_element(rest)?;
        rest = after;
    }
    // Whatever is here is the SPKI, header included — that is what gets hashed.
    let (_, after) = der_element(rest)?;
    Some(&rest[..rest.len() - after.len()])
}

/// Contents of the outermost SEQUENCE, then the first element inside it.
fn der_sequence(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (body, rest) = der_element(der)?;
    // First element of the certificate is tbsCertificate, itself a SEQUENCE.
    let (tbs, _) = der_element(body)?;
    Some((tbs, rest))
}

/// Split one DER element: returns its contents and everything after it.
fn der_element(der: &[u8]) -> Option<(&[u8], &[u8])> {
    if der.len() < 2 {
        return None;
    }
    let first_len = der[1];
    let (len, header) = if first_len & 0x80 == 0 {
        (first_len as usize, 2)
    } else {
        let n = (first_len & 0x7F) as usize;
        // A length field longer than a usize, or absent, is malformed.
        if n == 0 || n > 4 || der.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for &b in &der[2..2 + n] {
            len = (len << 8) | b as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    if der.len() < end {
        return None;
    }
    Some((&der[header..end], &der[end..]))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn machine_identity(
    ) -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>, String) {
        let certified =
            rcgen::generate_simple_self_signed(vec!["sysentinel".to_string()]).expect("cert");
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
            .expect("key");
        let pin = spki_pin(&cert).expect("pin");
        (cert, key, pin)
    }

    fn machine_server_cfg(
        cert: &rustls::pki_types::CertificateDer<'static>,
        key: &rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Arc<rustls::ServerConfig> {
        Arc::new(
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key.clone_key())
                .expect("server config"),
        )
    }

    /// Read lines off a TLS stream the way the daemon's `serve_io` does —
    /// enough of the wire protocol to stand in for it in these tests.
    fn tls_read_line(tls: &mut (impl Read + ?Sized), max: usize) -> std::io::Result<String> {
        let mut out = String::new();
        let mut byte = [0u8; 1];
        while out.len() <= max {
            match tls.read(&mut byte) {
                Ok(0) => return Ok(out),
                Ok(_) => {
                    out.push(byte[0] as char);
                    if byte[0] == b'\n' {
                        return Ok(out);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    fn fake_daemon(
        listener: std::net::TcpListener,
        token: String,
        cert: &rustls::pki_types::CertificateDer<'static>,
        key: &rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let cfg = machine_server_cfg(cert, key);
        std::thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(sock) = sock else { continue; };
                let cfg = Arc::clone(&cfg);
                let tok = token.clone();
                std::thread::spawn(move || {
                    let conn = rustls::ServerConnection::new(cfg).expect("conn");
                    let mut tls = rustls::StreamOwned::new(conn, sock);
                    match tls_read_line(&mut tls, 128) {
                        Ok(line) if line.trim() == tok => match tls_read_line(&mut tls, 1 << 20) {
                            Ok(line) => {
                                let answer = if line.contains("\"op\":\"ping\"") {
                                    "{\"ok\":{\"text\":\"pong\"}}\n".to_string()
                                } else {
                                    "{\"error\":{\"message\":\"no\"}}\n".to_string()
                                };
                                let _ = tls.write_all(answer.as_bytes());
                                let _ = tls.flush();
                            }
                            _ => {} // huffed on the request: hang up
                        },
                        _ => {} // wrong token: say nothing and hang up
                    }
                });
            }
        });
    }

    #[test]
    fn the_connect_string_parses_and_round_trips() {
        let r = parse_connect(
            "sysentinel://connect?addr=192.168.1.50:8888&pin=sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("valid connect string");
        assert_eq!(r.host, "192.168.1.50");
        assert_eq!(r.port, 8888);
        assert_eq!(r.pin, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert_eq!(r.token.len(), 64);

        // The pieces this GUI needs to talk are all present — knock on nothing
        // but at least confirm `describe` and `ask` routing resolve.
        let t = Target::Remote(r);
        assert!(t.describe().contains("client →"));

        let malformed = [
            "",
            "sysentinel://connect",
            "sysentinel://connect?addr=host:abc&pin=sha256/x&token=",
            "sysentinel://connect?addr=host:8000&pin=sha256/x&token=abcd",
            "sysentinel://connect?addr=host:8000&token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ];
        for m in malformed {
            assert!(parse_connect(m).is_err(), "should reject: {m:?}");
        }
    }

    #[test]
    fn a_client_with_pin_and_token_gets_a_pong_over_tls_13() {
        let (cert, key, pin) = machine_identity();
        let token = "a".repeat(64);

        // Bound in the foreground so the port exists before any client knocks.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        fake_daemon(listener, token.clone(), &cert, &key);

        let uri = format!(
            "sysentinel://connect?addr={addr}&pin={pin}&token={token}"
        );
        let remote = parse_connect(&uri).expect("parse");
        let text = ask_remote(&remote, crate::ipc::Request::Ping).expect("ask");
        assert_eq!(text, "pong");
    }

    #[test]
    fn bad_pin_and_bad_token_are_both_refused() {
        let (cert, key, pin) = machine_identity();
        let token = "a".repeat(64);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        fake_daemon(listener, token.clone(), &cert, &key);

        // Wrong token: handshake fine, daemon hangs up, client reports Rejected.
        let uri = format!(
            "sysentinel://connect?addr={addr}&pin={pin}&token={}",
            "0".repeat(64)
        );
        let remote = parse_connect(&uri).expect("parse");
        assert!(matches!(ask_remote(&remote, crate::ipc::Request::Ping), Err(RemoteError::Rejected)));

        // Wrong pin: the client refuses the certificate before any credential.
        let uri = format!(
            "sysentinel://connect?addr={addr}&pin=sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&token={token}"
        );
        let remote = parse_connect(&uri).expect("parse");
        let r = ask_remote(&remote, crate::ipc::Request::Ping);
        assert!(r.is_err(), "a wrong pin must not complete a session: {r:?}");
    }
}