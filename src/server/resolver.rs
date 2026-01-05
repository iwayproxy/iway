use std::{net::SocketAddr, sync::Arc};

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

#[derive(Debug)]
pub struct PeerAwareCertResolver {
    cert: Arc<CertifiedKey>,
    peer_addr: SocketAddr,
}

impl PeerAwareCertResolver {
    pub fn new(cert: Arc<CertifiedKey>, peer_addr: SocketAddr) -> Self {
        Self { cert, peer_addr }
    }
}

impl ResolvesServerCert for PeerAwareCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            tracing::debug!(
                "[Trojan] Suspicious TLS handshake: IP used as SNI, peer={} sni={}",
                self.peer_addr,
                sni
            );
        }

        Some(self.cert.clone())
    }
}
