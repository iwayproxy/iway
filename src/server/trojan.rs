use std::sync::Arc;
use std::time::Instant;

use crate::authenticate::trojan::TrojanAuthenticationManager;
use crate::processor::trojan::{RuntimeContext, TrojanConnectionProcessor};
use crate::server::tls::{build_certified_key, build_tls_acceptor, load_certs, load_key};

use super::{Server, ServerStatus};

use anyhow::{Context, Error, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch::Receiver;
use tracing::{debug, error, info};

use rustls::sign::CertifiedKey;
use std::path::PathBuf;

pub struct TrojanServer {
    name: &'static str,
    socket_addr: std::net::SocketAddr,
    listener: Option<TcpListener>,
    status: ServerStatus,
    processor: Arc<TrojanConnectionProcessor>,
    #[allow(dead_code)]
    fallback_addr: std::net::SocketAddr,
    #[allow(dead_code)]
    shutdown_rx: Option<Receiver<()>>,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

impl TrojanServer {
    pub fn new_with_config(
        config: crate::config::Config,
        shutdown_rx: Option<Receiver<()>>,
    ) -> Result<Self, Error> {
        let socket = config
            .trojan()
            .server_addr()
            .parse()
            .with_context(|| "Failed to parse server address")?;

        // initialized all users' data
        let passwords: Vec<String> = config
            .trojan()
            .users()
            .iter()
            .map(|u| u.password().to_string())
            .collect();

        let auth = Arc::new(TrojanAuthenticationManager::new(passwords));

        let fallback_addr: std::net::SocketAddr = config.trojan().fallback_addr().parse()?;

        let processor =
            Arc::new(TrojanConnectionProcessor::new(auth).with_fallback_addr(fallback_addr));

        Ok(Self {
            name: "Trojan",
            socket_addr: socket,
            listener: None,
            status: ServerStatus::Initializing(Instant::now()),
            processor,
            fallback_addr,
            shutdown_rx,
            cert_path: PathBuf::from(config.trojan().cert_path()),
            key_path: PathBuf::from(config.trojan().key_path()),
        })
    }
}

#[async_trait]
impl Server for TrojanServer {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn init(&mut self) -> Result<Instant, Error> {
        let instant = Instant::now();

        info!("[Trojan] Initializing server at {}", self.socket_addr);

        self.status = ServerStatus::Initializing(instant);

        info!("[Trojan] Initialization completed");

        Ok(instant)
    }

    async fn start(&mut self) -> Result<Instant, Error> {
        let instant = Instant::now();

        info!("[Trojan] Starting server at {}", self.socket_addr);

        let certs = load_certs(&self.cert_path)?;
        let key = load_key(&self.key_path)?;

        let cert_key = build_certified_key(certs, key)?;

        let listener = TcpListener::bind(self.socket_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", self.socket_addr))?;

        info!("[Trojan] Listening on {}", self.socket_addr);

        self.listener = Some(listener);

        if let Some(listener) = self.listener.take() {
            let processor = Arc::clone(&self.processor);
            // move shutdown receiver into accept loop
            let shutdown_rx = self.shutdown_rx.take();

            tokio::spawn(async move {
                if let Err(e) = accept_loop(listener, cert_key, processor, shutdown_rx).await {
                    error!("[Trojan] Accept loop exited with error: {}", e);
                }
            });
        }

        self.status = ServerStatus::Running(instant);

        info!("[Trojan] Server started");

        Ok(instant)
    }

    async fn stop(&mut self) -> Result<Instant, Error> {
        let instant = Instant::now();

        info!("[Trojan] Stopping server");

        self.listener = None;

        self.status = ServerStatus::Stopped(instant);

        info!("[Trojan] Server stopped");

        Ok(instant)
    }

    async fn status(&mut self) -> Result<&ServerStatus, Error> {
        Ok(&self.status)
    }
}

async fn accept_loop(
    listener: TcpListener,
    cert_key: Arc<CertifiedKey>,
    processor: Arc<TrojanConnectionProcessor>,
    mut shutdown_rx: Option<Receiver<()>>,
) -> Result<(), Error> {
    loop {
        // prepare accept future for select
        let accept_fut = listener.accept();

        if let Some(ref mut rx) = shutdown_rx {
            tokio::select! {
                biased;
                res = accept_fut => {
                    match res {
                        Ok((tcp_stream, peer_addr)) => {
                            debug!("[Trojan] Accepted connection from {}", peer_addr);
                            let key = Arc::clone(&cert_key);
                            let proc = Arc::clone(&processor);
                            tokio::spawn(handle_connection(tcp_stream, peer_addr, key, proc));
                        }
                        Err(e) => {
                            error!("[Trojan] Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = rx.changed() => {
                    info!("[Trojan] Shutdown signal received, stopping accept loop");
                    break;
                }
            }
        } else {
            match accept_fut.await {
                Ok((tcp_stream, peer_addr)) => {
                    debug!("[Trojan] Accepted connection from {}", peer_addr);
                    let key = Arc::clone(&cert_key);
                    let proc = Arc::clone(&processor);
                    tokio::spawn(handle_connection(tcp_stream, peer_addr, key, proc));
                }
                Err(e) => {
                    error!("[Trojan] Failed to accept connection: {}", e);
                }
            }
        }
    }

    Ok(())
}

// TLS helpers are implemented in `src/server/tls.rs`.

async fn handle_connection(
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    cert_key: Arc<CertifiedKey>,
    processor: Arc<TrojanConnectionProcessor>,
) {
    let tls_acceptor = build_tls_acceptor(cert_key, peer_addr);

    let tls_acceptor = match tls_acceptor {
        Ok(a) => a,
        Err(e) => {
            debug!("[Trojan] TLS acceptor not initialized {}", e);
            return;
        }
    };

    match tls_acceptor.accept(tcp_stream).await {
        Ok(tls_stream) => {
            debug!("[Trojan] TLS handshake completed with {}", peer_addr);
            let context = Arc::new(RuntimeContext::new(peer_addr.to_string()));

            if let Err(e) = processor.process_connection_tls(tls_stream, context).await {
                debug!("[Trojan] Connection processing error: {}", e);
            }
        }
        Err(e) => {
            info!(
                "[Trojan] TLS handshake failed with client IP: {}, Error: {}",
                peer_addr, e
            );
        }
    }
}
