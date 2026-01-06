use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::crypto;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::sign::CertifiedKey;
use rustls::{CipherSuite, ServerConfig};
use tokio_rustls::TlsAcceptor;

use crate::server::resolver::PeerAwareCertResolver;

pub fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open certificate file: {:?}", path))?;

    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| "Failed to parse certificates!")?;

    if certs.is_empty() {
        anyhow::bail!("No certificates found in file");
    }

    Ok(certs)
}

pub fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open private key file: {:?}", path))?;

    let mut reader = BufReader::new(file);
    let keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to parse private keys from file: {:?}", path))?;

    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No private keys found in file"))?;

    Ok(key.into())
}

pub fn build_certified_key(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>> {
    let signing_key = any_supported_type(&key).context("invalid private key")?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

pub fn build_tls_acceptor(
    base_cert: Arc<CertifiedKey>,
    peer_addr: SocketAddr,
) -> Result<TlsAcceptor> {
    let resolver = Arc::new(PeerAwareCertResolver::new(base_cert, peer_addr));

    let mut provider = crypto::ring::default_provider();
    provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            CipherSuite::TLS13_AES_256_GCM_SHA384 | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        )
    });

    static TLS_PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(TLS_PROTOCOL_VERSIONS)
        .with_context(|| "Failed to set TLS protocol versions!")?
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    Ok(TlsAcceptor::from(Arc::new(config)))
}
