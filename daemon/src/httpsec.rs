// SPDX-License-Identifier: Apache-2.0
//!
//! The daemon's outbound HTTP, hardened.
//!
//! There is exactly one thing this daemon still sends to somebody else's
//! server: LLM requests. Those carry an API key in a header and, in the body,
//! a description of what just happened on the machine — kernel events, hardware
//! detail, sometimes the reason a login looked wrong. That is worth protecting
//! properly rather than assuming a URL in a config file is safe.
//!
//! Two problems are closed here.
//!
//! # 1. Nothing validated the scheme
//!
//! A `base_url` of `http://…` was accepted and used. The API key would have
//! gone out in plaintext, along with the request body, to anyone on the path.
//! Nothing warned; it simply worked. [`require_https`] rejects it at config
//! load and again at request time, because a config can be edited after it is
//! validated.
//!
//! # 2. Any CA in the store could impersonate the provider
//!
//! Public CA validation answers "did *a* trusted CA vouch for this name", and
//! a browser trust store contains well over a hundred of them. Any one, or
//! anything that can make one issue, can stand in the middle. For a fixed set
//! of endpoints that never changes, that is far more trust than the job needs.
//!
//! [`pinned_agent`] pins the **public key** (SPKI SHA-256), not the
//! certificate. Providers rotate certificates routinely and usually keep the
//! key, so a certificate pin breaks on a Tuesday for no security reason while
//! an SPKI pin survives — and a pin that breaks gets deleted, which is worse
//! than not pinning.
//!
//! Pinning is **opt-in and additive**: chain validation still happens first,
//! and the pin is checked on top. A wrong pin fails closed. Off by default,
//! because a stale pin turns into an outage and that decision belongs to
//! whoever operates the machine.

use std::sync::Arc;

use anyhow::{Context, Result};
use aws_lc_rs::digest;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// Reject anything that is not HTTPS.
///
/// Checked at config load *and* before each request: a file can be edited
/// between the two, and this is the one place a mistake silently costs an API
/// key.
pub fn require_https(url: &str) -> Result<()> {
    let lower = url.trim().to_ascii_lowercase();
    anyhow::ensure!(
        !lower.starts_with("http://"),
        "refusing to use {url} — that is plain HTTP, so the API key and \
         everything this daemon tells the model would travel in the clear. \
         Use https://."
    );
    anyhow::ensure!(
        lower.starts_with("https://"),
        "refusing to use {url} — expected an https:// URL"
    );
    Ok(())
}

/// Base64url-encoded SHA-256 of a certificate's SubjectPublicKeyInfo, in the
/// shape people publish pins in (`sha256/…`).
pub fn spki_pin(cert: &CertificateDer<'_>) -> Result<String> {
    // The SPKI is a field inside the certificate; extracting it without a full
    // X.509 parser means walking the DER far enough to find it.
    let spki = extract_spki(cert.as_ref())
        .context("httpsec: could not find the SubjectPublicKeyInfo in this certificate")?;
    let sum = digest::digest(&digest::SHA256, spki);
    Ok(format!("sha256/{}", base64_std(sum.as_ref())))
}

/// Standard base64 with padding — the form pin lists use.
fn base64_std(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(A[(n >> 18 & 63) as usize] as char);
        out.push(A[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 { A[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Walk a DER certificate to its SubjectPublicKeyInfo.
///
/// A Certificate is `SEQUENCE { tbsCertificate, signatureAlgorithm, signature }`
/// and the SPKI is the seventh field of tbsCertificate — after the optional
/// version tag, serial, signature, issuer, validity and subject. Counting them
/// is enough; nothing here needs to understand what they contain.
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

/// Chain validation first, then the pin.
#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    /// Accepted `sha256/…` pins. A match anywhere in the chain is enough, so a
    /// pin may name a leaf or an intermediate the operator considers stable.
    pins: Vec<String>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        // Additive, never instead of: an expired or misissued certificate is
        // rejected here even if its key is pinned.
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;

        let matched = std::iter::once(end_entity)
            .chain(intermediates)
            .filter_map(|c| spki_pin(c).ok())
            .any(|p| self.pins.contains(&p));

        if matched {
            Ok(ServerCertVerified::assertion())
        } else {
            // Say what was presented, so a rotation that changed the key can be
            // fixed by pasting a line rather than by packet capture.
            let seen: Vec<String> = std::iter::once(end_entity)
                .chain(intermediates)
                .filter_map(|c| spki_pin(c).ok())
                .collect();
            log::error!(
                "httpsec: certificate pin mismatch for {server_name:?}. Chain presented: {}. \
                 Configured pins: {}. If the provider rotated keys, update [llm] tls_pins.",
                seen.join(", "),
                self.pins.join(", ")
            );
            Err(TlsError::General("certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(m, c, d)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// An agent for outbound LLM calls.
///
/// With `pins` empty this is ordinary HTTPS with public CA validation. With
/// pins, the chain must also carry one of them.
pub fn agent(pins: &[String]) -> Result<ureq::Agent> {
    // rustls 0.23 refuses to guess when more than one crypto backend is
    // reachable, and panics rather than picking. The daemon already uses
    // aws-lc-rs for the TPM key and the phone frames, so say so once — a panic
    // deep inside a TLS handshake is a miserable way to learn this.
    install_crypto_provider();

    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let config = if pins.is_empty() {
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        for p in pins {
            anyhow::ensure!(
                p.starts_with("sha256/") && p.len() > 7,
                "tls_pins entries look like `sha256/<base64>`, got {p:?}"
            );
        }
        let webpki = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .context("httpsec: building the certificate verifier")?;
        let verifier = Arc::new(PinnedVerifier { inner: webpki, pins: pins.to_vec() });
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    };

    Ok(ureq::AgentBuilder::new().tls_config(Arc::new(config)).build())
}

/// The process's outbound agent, built once from the configured pins.
///
/// One agent rather than one per request: it holds the TLS config and a
/// connection pool, and rebuilding it per call would both re-verify pins
/// needlessly and throw away keep-alive.
static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();

/// Build the shared agent. Call once at startup, before any request.
pub fn init(pins: &[String]) -> Result<()> {
    let a = agent(pins)?;
    if AGENT.set(a).is_err() {
        log::warn!("httpsec: the outbound agent was already built — ignoring");
    }
    if pins.is_empty() {
        log::info!("httpsec: outbound HTTPS with public CA validation (no pins configured)");
    } else {
        log::info!("httpsec: outbound HTTPS pinned to {} key(s)", pins.len());
    }
    Ok(())
}

/// The shared agent, falling back to an unpinned one if `init` was never
/// called. Unpinned is what the daemon did before pinning existed, so the
/// fallback loses nothing that was ever there — but it is logged, because
/// silently not pinning is exactly the failure worth noticing.
pub fn shared() -> ureq::Agent {
    if let Some(a) = AGENT.get() {
        return a.clone();
    }
    log::warn!("httpsec: outbound agent used before init() — falling back to unpinned HTTPS");
    agent(&[]).unwrap_or_else(|_| ureq::Agent::new())
}

/// Install aws-lc-rs as the process TLS backend, once.
fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .is_err()
        {
            // Already installed by something else: fine, and not worth a word.
            log::debug!("httpsec: a TLS crypto provider was already installed");
        }
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_refused_with_a_reason() {
        // The hole this closes: an http:// base_url sent the API key in the
        // clear and nothing said a word.
        let err = require_https("http://api.example.com/v1").unwrap_err().to_string();
        assert!(err.contains("plain HTTP"), "{err}");
        assert!(err.contains("in the clear"), "{err}");

        assert!(require_https("HTTP://API.EXAMPLE.COM").is_err(), "case must not evade it");
        assert!(require_https("ftp://example.com").is_err());
        assert!(require_https("api.example.com").is_err(), "no scheme is not https");
        assert!(require_https("").is_err());

        assert!(require_https("https://api.anthropic.com/v1").is_ok());
        assert!(require_https("  https://api.openai.com/v1  ").is_ok());
    }

    #[test]
    fn base64_matches_the_form_pins_are_published_in() {
        assert_eq!(base64_std(b""), "");
        assert_eq!(base64_std(b"f"), "Zg==");
        assert_eq!(base64_std(b"fo"), "Zm8=");
        assert_eq!(base64_std(b"foo"), "Zm9v");
        assert_eq!(base64_std(b"foob"), "Zm9vYg==");
        assert_eq!(base64_std(b"foobar"), "Zm9vYmFy");
        // A SHA-256 digest is 32 bytes: 44 characters with one '=' of padding.
        let d = digest::digest(&digest::SHA256, b"x");
        let e = base64_std(d.as_ref());
        assert_eq!(e.len(), 44);
        assert!(e.ends_with('='));
    }

    #[test]
    fn der_walking_survives_malformed_input() {
        // This parses attacker-adjacent bytes, so it must return None rather
        // than panic on anything short, truncated or absurd.
        assert!(der_element(&[]).is_none());
        assert!(der_element(&[0x30]).is_none());
        assert!(der_element(&[0x30, 0x05, 0x00]).is_none(), "length beyond the buffer");
        assert!(der_element(&[0x30, 0x85, 1, 2, 3, 4, 5]).is_none(), "5-byte length");
        assert!(der_element(&[0x30, 0x80]).is_none(), "indefinite length");
        assert!(extract_spki(&[]).is_none());
        assert!(extract_spki(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_none());

        // A short definite length parses.
        let (body, rest) = der_element(&[0x02, 0x01, 0x2A, 0xFF]).unwrap();
        assert_eq!(body, &[0x2A]);
        assert_eq!(rest, &[0xFF]);
    }

    #[test]
    fn an_agent_builds_with_and_without_pins() {
        assert!(agent(&[]).is_ok(), "no pins is ordinary HTTPS");
        assert!(agent(&["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()]).is_ok());
    }

    #[test]
    fn a_malformed_pin_is_refused_at_build_time() {
        // Better here than as a handshake failure the first time the LLM is
        // called, which would look like the provider being down.
        for bad in ["", "sha256/", "deadbeef", "sha1/abc", "AAAA"] {
            assert!(
                agent(&[bad.to_string()]).is_err(),
                "{bad:?} should not be accepted as a pin"
            );
        }
    }

    #[test]
    fn a_real_certificate_yields_a_stable_pin() {
        // Self-signed, generated once and pasted here: the point is that the
        // DER walk finds an SPKI and hashes it the same way every time.
        let der = include_bytes!("testdata/pin-sample.der");
        let cert = CertificateDer::from(der.to_vec());
        let pin = spki_pin(&cert).expect("a well-formed certificate must yield a pin");

        // The value openssl computes for the same certificate:
        //   openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
        //     | openssl dgst -sha256 -binary | openssl enc -base64
        //
        // Matching a second implementation is the point. "It is deterministic"
        // would pass just as happily on a pin that hashes the wrong bytes, and
        // a wrong pin only shows up as a handshake failure against a live
        // provider, which reads like an outage.
        assert_eq!(pin, "sha256/Rvrhgdz6aGp8mihvuVcRaqf7u0VEwVfqiivpmmDQOrs=");
    }
}

#[cfg(test)]
mod live_pin {
    /// Opt-in: needs the network.
    ///
    ///   SYSENTINEL_PIN_HOST=api.anthropic.com SYSENTINEL_PIN=sha256/... \
    ///     cargo test --manifest-path daemon/Cargo.toml live_pin -- --nocapture
    #[test]
    fn a_good_pin_connects_and_a_wrong_one_does_not() {
        let (Ok(host), Ok(pin)) = (
            std::env::var("SYSENTINEL_PIN_HOST"),
            std::env::var("SYSENTINEL_PIN"),
        ) else {
            println!("set SYSENTINEL_PIN_HOST and SYSENTINEL_PIN to run this");
            return;
        };
        let url = format!("https://{host}/");

        // The right pin: the handshake completes, so any HTTP status at all is
        // a pass — 404 and 401 both mean TLS worked.
        let good = super::agent(&[pin.clone()]).unwrap();
        match good.get(&url).call() {
            Ok(_) => println!("pinned handshake: ok"),
            Err(ureq::Error::Status(code, _)) => println!("pinned handshake: ok (HTTP {code})"),
            Err(e) => panic!("the correct pin should have connected: {e}"),
        }

        // A wrong pin must fail closed, and must NOT fail as an HTTP status —
        // that would mean the connection happened anyway.
        let bad = super::agent(&["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()])
            .unwrap();
        match bad.get(&url).call() {
            Err(ureq::Error::Transport(_)) => println!("wrong pin: refused, as it must be"),
            other => panic!("a wrong pin must not connect, got {other:?}"),
        }
    }
}
