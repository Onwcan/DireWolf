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

use std::path::Path;
use std::sync::Arc;

use rustls::client::Resumption;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use rustls::{ClientConfig, RootCertStore};

/// The one ALPN protocol offered.
pub(crate) const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// The most bytes an evidence trust anchor file may hold.
const ANCHOR_MAX_BYTES: u64 = 64 * 1024;

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

/// Production: Mozilla's roots, compiled in.
///
/// # Errors
///
/// The configuration does not build — a defect, never an input.
pub(crate) fn production() -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    config(roots)
}

/// Evidence only: the certificates in `pem` as the **only** roots. The
/// broker's `--allow-evidence-trust`, and nothing else, calls this.
///
/// # Errors
///
/// The file cannot be read, is too large, holds no certificate, or a
/// certificate is not a usable trust anchor.
pub(crate) fn evidence(pem: &Path) -> Result<Arc<ClientConfig>, String> {
    let size = std::fs::metadata(pem)
        .map_err(|e| format!("{}: {:?}", pem.display(), e.kind()))?
        .len();
    if size > ANCHOR_MAX_BYTES {
        return Err("the evidence trust anchor file is too large".to_owned());
    }
    let mut roots = RootCertStore::empty();
    let mut count = 0usize;
    for certificate in
        CertificateDer::pem_file_iter(pem).map_err(|e| format!("{}: {e}", pem.display()))?
    {
        let certificate = certificate.map_err(|e| format!("{}: {e}", pem.display()))?;
        roots
            .add(certificate)
            .map_err(|e| format!("{}: not a trust anchor: {e}", pem.display()))?;
        count = count.saturating_add(1);
    }
    if count == 0 {
        return Err(format!("{}: no certificate", pem.display()));
    }
    config(roots)
}

#[cfg(test)]
mod tests {
    use super::{ALPN_HTTP_1_1, production};

    #[test]
    fn production_offers_one_protocol_and_resumes_nothing() {
        let config = production().unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(config.alpn_protocols, vec![ALPN_HTTP_1_1.to_vec()]);
        assert!(config.enable_sni);
        assert!(!config.enable_early_data);
        // No key log: the default writes nothing anywhere.
        assert!(!config.key_log.will_log("CLIENT_RANDOM"));
    }
}
