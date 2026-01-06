use std::sync::Arc;
use std::time::Instant;

use crate::authenticate::trojan::TrojanAuthenticationManager;
use crate::processor::trojan::{RuntimeContext, TrojanConnectionProcessor};
use crate::server::tls::{build_certified_key, build_tls_acceptor, load_certs, load_key};

use super::{Server, ServerStatus};

use anyhow::{Context, Error, Result};
use async_trait::async_trait;
use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch::Receiver;
use tokio::time::{Duration, timeout};
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
        config: std::sync::Arc<crate::config::Config>,
        shutdown_rx: Option<Receiver<()>>,
    ) -> Result<Self, Error> {
        let socket = config
            .trojan()
            .server_addr()
            .parse()
            .with_context(|| "Failed to parse server address")?;

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

    struct PrebufferedStream<S> {
        buf: Cursor<Vec<u8>>,
        stream: S,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for PrebufferedStream<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf_out: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let remaining =
                (self.buf.get_ref().len() as u64).saturating_sub(self.buf.position()) as usize;
            if remaining > 0 {
                let to_copy = std::cmp::min(remaining, buf_out.remaining());
                let pos = self.buf.position() as usize;
                let slice = &self.buf.get_ref()[pos..pos + to_copy];
                buf_out.put_slice(slice);
                self.buf.set_position((pos + to_copy) as u64);
                return Poll::Ready(Ok(()));
            }

            Pin::new(&mut self.stream).poll_read(cx, buf_out)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for PrebufferedStream<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    let mut tcp_stream = tcp_stream;
    let mut tmp = [0u8; 5];
    let mut prebuf = Vec::new();
    match timeout(Duration::from_millis(200), tcp_stream.read(&mut tmp)).await {
        Ok(Ok(n)) => {
            if n > 0 {
                prebuf.extend_from_slice(&tmp[..n]);
            }
        }
        Ok(Err(e)) => {
            debug!(
                "[Trojan] Error reading initial bytes from {}: {}",
                peer_addr, e
            );
        }
        Err(_) => {}
    }

    if prebuf.len() >= 2 && !(prebuf[0] == 0x16 && prebuf[1] == 0x03) {
        let sample_hex: String = prebuf
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        debug!(
            "[Trojan] Non-TLS probe on TLS port from {}: {}",
            peer_addr, sample_hex
        );

        let _ = tcp_stream.shutdown().await;
        return;
    }

    let stream = PrebufferedStream {
        buf: Cursor::new(prebuf),
        stream: tcp_stream,
    };

    match tls_acceptor.accept(stream).await {
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
