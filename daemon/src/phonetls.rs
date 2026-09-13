// SPDX-License-Identifier: Apache-2.0
//!
//! TLS 1.3 underneath the phone channel.
//!
//! # What was here before, and what was wrong with it
//!
//! The channel sealed each frame with AES-256-GCM under the pairing key and
//! sent it over a bare TCP socket. Every primitive came from a library —
//! `aws-lc-rs` on this end, `javax.crypto` on the phone — so nothing was
//! *implementing* crypto. But the composition was mine: a hand-rolled record
//! layer with no handshake, and a protocol nobody has analysed is its own kind
//! of home-made cryptography even when every function it calls is vetted.
//!
//! Three properties were missing, and the first is the one that matters:
//!
//! - **No forward secrecy.** One long-lived pre-shared key protected
//!   everything, so anyone who recorded the traffic and *later* obtained the
//!   pairing key — off a backup, off a photograph of the QR, out of a future
//!   compromise — could decrypt every session that had ever happened. For a
//!   tool whose entire premise is that somebody may come for your machine
//!   afterwards, that is the wrong shape.
//! - **One key in both directions,** with no separation and no rekeying over
//!   a long-lived connection.
//! - **No analysed handshake.** "The first frame must decrypt" is an
//!   authentication scheme I invented on a Tuesday.
//!
//! TLS 1.3 has all three, written by people who do this for a living, and
//! `rustls` is already a dependency for the outbound side.
//!
//! # Why the AEAD frames stay inside
//!
//! They are not redundant, and they are not there out of superstition. This
//! server presents a self-signed certificate, which authenticates the
//! *machine to the phone* once the phone has pinned it. Nothing in that
//! authenticates the phone to the machine — TLS client certificates would, but
//! the phone's identity already lives in a key inside its secure element, and
//! that key answers a challenge one layer up.
//!
//! So the layers do different jobs: TLS makes the conversation private and
//! forward-secret, the AEAD frame proves the peer holds the pairing key, and
//! the device signature proves it is *that* handset. Keeping the frames also
//! means that if I have wired this TLS layer up wrong, the channel is no worse
//! than it was yesterday.
//!
//! # The certificate is pinned, not validated
//!
//! There is no CA here and there should not be: the machine answers on a LAN
//! address, a VPN address or a tunnel, none of which any public CA will ever
//! certify. So it signs its own, and the QR carries the SHA-256 of that
//! certificate's public key. The phone accepts exactly that key and nothing
//! else — the same trick as `[llm] tls_pins` for outbound, pointed the other
//! way. A name-based check would prove nothing here; the key is the identity.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Where the machine keeps its own certificate, beside the rest of its state.
const CERT_FILE: &str = "phone-cert.der";
const KEY_FILE: &str = "phone-key.der";

/// The machine's own certificate and the key that goes with it.
pub struct TlsIdentity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    /// `sha256/…` over the certificate's SubjectPublicKeyInfo — what the QR
    /// carries and the phone pins.
    pub fingerprint: String,
}

impl TlsIdentity {
    /// Load the stored identity, or mint one on first use.
    ///
    /// Regenerating would silently invalidate every pairing, so an existing
    /// pair of files is used as-is and only a missing one triggers a new key.
    pub fn load_or_create(dir: &Path) -> Result<TlsIdentity> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("phonetls: creating {}", dir.display()))?;
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);

        if cert_path.exists() && key_path.exists() {
            let cert = CertificateDer::from(std::fs::read(&cert_path)?);
            let key = PrivateKeyDer::try_from(std::fs::read(&key_path)?)
                .map_err(|e| anyhow::anyhow!("phonetls: {} is not a usable key: {e}", key_path.display()))?;
            let fingerprint = crate::httpsec::spki_pin(&cert)?;
            return Ok(TlsIdentity { cert, key, fingerprint });
        }

        let (cert, key) = generate()?;
        // 0600 from creation. The private half of this key is what lets
        // something claim to be this machine.
        write_private(&key_path, key.secret_der())?;
        std::fs::write(&cert_path, cert.as_ref())
            .with_context(|| format!("phonetls: writing {}", cert_path.display()))?;
        let fingerprint = crate::httpsec::spki_pin(&cert)?;
        log::info!("phone: minted a TLS identity for this machine ({fingerprint})");
        Ok(TlsIdentity { cert, key, fingerprint })
    }

    /// A TLS 1.3 server configuration for this identity.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        crate::httpsec::install_crypto_provider();
        let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            // No client certificate. The phone proves itself with the pairing
            // key and its device signature, one layer up, where the proof is
            // bound to hardware that cannot export it.
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
            .context("phonetls: building the server configuration")?;
        Ok(Arc::new(config))
    }
}

/// Accepts exactly one public key and refuses everything else.
///
/// No CA, no name check, and that is the design rather than a shortcut: this
/// server answers on a LAN address, a VPN address or a tunnel, and no public
/// authority will ever certify any of those. The phone is handed the key's
/// fingerprint by hand, in the QR, which is the strongest introduction
/// available — stronger than a name signed by one of a hundred CAs, since
/// nobody but this machine holds the private half.
///
/// The Android client implements the same policy against the same pin, so
/// this is also what the tests exercise.
// Constructed through `client_config_pinned`, and by the Android client's
// equivalent. Kept public because a Rust client of this channel is a thing
// that may well exist later.
#[allow(dead_code)]
#[derive(Debug)]
pub struct PinnedServerVerifier {
    pin: String,
}

impl PinnedServerVerifier {
    #[allow(dead_code)]
    pub fn new(pin: impl Into<String>) -> Self {
        PinnedServerVerifier { pin: pin.into() }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match crate::httpsec::spki_pin(end_entity) {
            Ok(seen) if seen == self.pin => {
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
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
/// A client configuration that trusts only `pin`.
///
/// Used by the tests here and by anything on this machine that ever needs to
/// talk to the phone channel as a client; the handset does the same thing with
/// the platform TLS stack.
#[allow(dead_code)] // the shipping client of this is the Android app
pub fn client_config_pinned(pin: &str) -> Result<Arc<rustls::ClientConfig>> {
    crate::httpsec::install_crypto_provider();
    let verifier = Arc::new(PinnedServerVerifier::new(pin));
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    ))
}

/// Mint a fresh self-signed P-256 certificate.
///
/// `rcgen` writes the X.509 — the alternative was hand-encoding DER, which is
/// the kind of thing this module exists to avoid. It is pinned to the
/// `aws-lc-rs` backend so the whole repository has one crypto implementation
/// rather than several with different bug histories.
fn generate() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    // The name is a placeholder on purpose: the phone pins the public key, so
    // a hostname here would be decoration. Putting a real address in would be
    // worse than useless — the address changes when the owner travels, and a
    // certificate that expires the moment they move house is a support
    // problem dressed up as security.
    let mut params = rcgen::CertificateParams::new(vec!["sysentinel".to_string()])
        .context("phonetls: certificate parameters")?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "sysentinel phone channel");
    // Ten years. A self-signed certificate that only ever gets checked against
    // a pin does not get safer by expiring; it just stops working one morning
    // for a reason nobody remembers.
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2100, 1, 1);

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("phonetls: generating the key pair")?;
    let cert = params
        .self_signed(&key)
        .context("phonetls: self-signing the certificate")?;

    let key_der = PrivateKeyDer::try_from(key.serialize_der())
        .map_err(|e| anyhow::anyhow!("phonetls: the generated key is not usable: {e}"))?;
    Ok((cert.der().clone(), key_der))
}

fn write_private(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("phonetls: creating {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("phonetls: writing {}", path.display()))?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sysentinel-tls-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn the_identity_is_minted_once_and_kept() {
        // Regenerating would invalidate every pairing without saying so.
        let dir = tmpdir("persist");
        let first = TlsIdentity::load_or_create(&dir).unwrap();
        let again = TlsIdentity::load_or_create(&dir).unwrap();
        assert_eq!(first.fingerprint, again.fingerprint);
        assert!(first.fingerprint.starts_with("sha256/"), "{}", first.fingerprint);

        // And the private half is owner-only from the moment it exists.
        let mode = std::fs::metadata(dir.join(KEY_FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // A different machine gets a different identity.
        let other = tmpdir("persist2");
        let elsewhere = TlsIdentity::load_or_create(&other).unwrap();
        assert_ne!(first.fingerprint, elsewhere.fingerprint);

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn a_client_that_pins_the_key_completes_a_tls_13_handshake() {
        // The whole point: a real handshake from a real library, end to end,
        // over a loopback socket — not a claim in a comment.
        let dir = tmpdir("handshake");
        let identity = TlsIdentity::load_or_create(&dir).unwrap();
        let expected_pin = identity.fingerprint.clone();
        let server_cfg = identity.server_config().unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).unwrap();
            tls.write_all(b"pong").unwrap();
            tls.flush().unwrap();
            tls.conn.protocol_version()
        });

        // Client: pins the key, ignores the name — there is no CA and the
        // address changes with the network, so the key IS the identity.
        let client_cfg = client_config_pinned(&expected_pin).unwrap();
        let name = rustls::pki_types::ServerName::try_from("sysentinel").unwrap();
        let conn = rustls::ClientConnection::new(client_cfg, name).unwrap();
        let sock = std::net::TcpStream::connect(addr).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(b"ping!").unwrap();
        tls.flush().unwrap();
        let mut back = [0u8; 4];
        tls.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"pong");

        assert_eq!(tls.conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
        assert_eq!(server.join().unwrap(), Some(rustls::ProtocolVersion::TLSv1_3));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_client_pinning_the_wrong_key_gets_nothing() {
        // The pin is the only thing standing between the phone and whoever
        // answers on that address, so a mismatch has to end the handshake —
        // not warn, not continue.
        let dir = tmpdir("wrongpin");
        let identity = TlsIdentity::load_or_create(&dir).unwrap();
        let server_cfg = identity.server_config().unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let mut buf = [0u8; 1];
            // Expected to fail: the client refuses the certificate.
            let _ = tls.read(&mut buf);
        });

        let client_cfg =
            client_config_pinned("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let name = rustls::pki_types::ServerName::try_from("sysentinel").unwrap();
        let conn = rustls::ClientConnection::new(client_cfg, name).unwrap();
        let sock = std::net::TcpStream::connect(addr).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        assert!(
            tls.write_all(b"ping!").and_then(|_| tls.flush()).is_err(),
            "a wrong pin must not complete a handshake"
        );

        let _ = server.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

}
