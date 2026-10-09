//! The HTTPS client's TLS configuration (M5c, ADR-0050 §9, D1): `rustls` with
//! `ring`, TLS 1.3 and 1.2, verification always on, the certificate checked
//! against the canonical host the authority authorised, that host as the
//! server name, `http/1.1` the only ALPN protocol, no client certificate, no
//! session resumption across exchanges, no early data, no key log.
//!
//! **One trust store per broker, chosen at start.** Production trusts
//! Mozilla's root store compiled in (`webpki-roots`): never the host's store,
//! never `SSL_CERT_FILE` or `SSL_CERT_DIR`, never anything the environment
//! names (TX046). The evidence harness alone may replace it with its own test
//! authority (`--allow-evidence-trust <pem>`, said loudly at start); the
//! evidence anchor **replaces** the roots rather than joining them, so an
//! evidence broker trusts nothing a production one does.
//!
//! There is no verifier override here, and no way to build one: the only
//! verifier is `rustls`'s `WebPKI` verifier over the store above.
//!
//! The choice is a [`Trust`] value, made once at start: each exchange's
//! short-lived worker (`super::worker`) is handed it by the broker that
//! spawned it, and builds the same configuration from it -- the worker reads
//! no file, no flag and no environment of its own.

use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use rustls::client::Resumption;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use rustls::{ClientConfig, RootCertStore};

/// The one ALPN protocol offered.
pub(crate) const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// The most bytes an evidence trust anchor file may hold.
pub(crate) const ANCHOR_MAX_BYTES: usize = 64 * 1024;

/// The roots the client trusts, chosen once at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Trust {
    /// Mozilla's, compiled in.
    Production,
    /// Evidence only: a test authority's certificates, as their PEM text --
    /// the **only** roots.
    Evidence(Vec<u8>),
}

impl Trust {
    /// Evidence only: the certificates in the file `pem`, checked here so a
    /// broker with an unusable anchor refuses to start.
    ///
    /// # Errors
    ///
    /// The file cannot be read, is too large, holds no certificate, or a
    /// certificate is not a usable trust anchor.
    pub(crate) fn evidence(pem: &Path) -> Result<Self, String> {
        let file =
            std::fs::File::open(pem).map_err(|e| format!("{}: {:?}", pem.display(), e.kind()))?;
        let mut text = Vec::new();
        file.take(
            u64::try_from(ANCHOR_MAX_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut text)
        .map_err(|e| format!("{}: {:?}", pem.display(), e.kind()))?;
        if text.len() > ANCHOR_MAX_BYTES {
            return Err("the evidence trust anchor file is too large".to_owned());
        }
        let trust = Self::Evidence(text);
        trust
            .config()
            .map_err(|e| format!("{}: {e}", pem.display()))?;
        Ok(trust)
    }

    /// The client configuration over these roots.
    ///
    /// # Errors
    ///
    /// The configuration does not build, or the evidence text holds no usable
    /// certificate.
    pub(crate) fn config(&self) -> Result<Arc<ClientConfig>, String> {
        let mut roots = RootCertStore::empty();
        match self {
            Self::Production => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            Self::Evidence(pem) => {
                let mut count = 0usize;
                for certificate in CertificateDer::pem_slice_iter(pem) {
                    let certificate = certificate.map_err(|e| format!("the anchor: {e}"))?;
                    roots
                        .add(certificate)
                        .map_err(|e| format!("not a trust anchor: {e}"))?;
                    count = count.saturating_add(1);
                }
                if count == 0 {
                    return Err("no certificate".to_owned());
                }
            }
        }
        config(roots)
    }
}

/// A configuration over `roots`.
fn config(roots: RootCertStore) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| format!("the TLS configuration: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_sni = true;
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::{ALPN_HTTP_1_1, Trust};

    #[test]
    fn production_offers_one_protocol_and_resumes_nothing() {
        let config = Trust::Production
            .config()
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(config.alpn_protocols, vec![ALPN_HTTP_1_1.to_vec()]);
        assert!(config.enable_sni);
        assert!(!config.enable_early_data);
        // No key log: the default writes nothing anywhere.
        assert!(!config.key_log.will_log("CLIENT_RANDOM"));
    }

    #[test]
    fn an_evidence_anchor_must_hold_a_usable_certificate() {
        assert!(Trust::Evidence(Vec::new()).config().is_err());
        assert!(Trust::Evidence(b"not pem".to_vec()).config().is_err());
    }
}
