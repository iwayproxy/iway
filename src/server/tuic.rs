use std::fs::File;
use std::io::{self, BufReader, ErrorKind};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use std::{io::Error, net::SocketAddr, path::Path, time::Instant};

use crate::processor::tuic::command::{NotifyState, OneShotNotifier};
use crate::processor::tuic::TuicConnectionProcessor;
use crate::processor::ConnectionProcessor;

use super::{Server, ServerStatus};

use async_trait::async_trait;
use log::{debug, info};
use quinn::congestion::BbrConfig;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig, VarInt};
use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;
use rustls::crypto::{self, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::CipherSuite;
use rustls_pemfile::{certs, private_key};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::sync::watch::Receiver;

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to open certificate file: {}", e),
        )
    })?;

    let certs: io::Result<Vec<_>> = certs(&mut BufReader::new(file)).collect();
    let certs = certs.map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to parse certificates: {}", e),
        )
    })?;

    if certs.is_empty() {
        return Err(io::Error::new(
            ErrorKind::Other,
            "No certificates found in file",
        ));
    }

    Ok(certs)
}

fn load_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("Failed to open key file: {}", e)))?;

    let key = private_key(&mut BufReader::new(file))
        .map_err(|e| {
            io::Error::new(
                ErrorKind::Other,
                format!("Failed to parse private key: {}", e),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(ErrorKind::Other, "No private key found in file".to_string())
        })?;

    Ok(key)
}

pub static TLS_PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

pub static CRYPTO_PROVIDER: LazyLock<Arc<CryptoProvider>> = LazyLock::new(|| {
    let mut provider = crypto::aws_lc_rs::default_provider();

    provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            CipherSuite::TLS13_AES_256_GCM_SHA384 | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        )
    });

    Arc::new(provider)
});

pub struct TuicServer {
    socket: SocketAddr,
    ep: Option<Endpoint>,
    status: ServerStatus,
    processor: Arc<TuicConnectionProcessor>,
    cert_path: PathBuf,
    key_path: PathBuf,

    shutdown_rx: Option<Receiver<()>>,
}

impl TuicServer {
    pub fn new_with_config(
        config: crate::config::Config,
        shutdown_rx: Option<Receiver<()>>,
    ) -> Result<Self, Error> {
        let socket = config.server_addr.parse().map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid server address: {}", e),
            )
        })?;

        let user_entries = config
            .users
            .iter()
            .filter_map(|u| {
                uuid::Uuid::parse_str(&u.uuid)
                    .ok()
                    .map(|id| (id, u.password.clone()))
            })
            .collect::<Vec<_>>();

        Ok(Self {
            socket,
            ep: None,
            status: ServerStatus::Initializing(Instant::now()),
            processor: Arc::new(TuicConnectionProcessor::new(user_entries)),
            cert_path: PathBuf::from(config.cert_path),
            key_path: PathBuf::from(config.key_path),
            shutdown_rx: shutdown_rx,
        })
    }
}

#[async_trait]
impl Server for TuicServer {
    async fn init(&mut self) -> Result<Instant, Error> {
        let certs = load_certs(&self.cert_path)?;
        let key = load_key(&self.key_path)?;

        let mut rustls_config =
            rustls::ServerConfig::builder_with_provider(CRYPTO_PROVIDER.clone())
                .with_protocol_versions(TLS_PROTOCOL_VERSIONS)
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("Failed to set TLS protocol versions: {}", e),
                    )
                })?
                .with_no_client_auth()
                .with_single_cert(certs, key.into())
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("Failed to configure TLS certificate: {}", e),
                    )
                })?;

        rustls_config.alpn_protocols = vec![b"h3".to_vec()];
        rustls_config.max_early_data_size = u32::MAX;
        rustls_config.send_half_rtt_data = true;

        let quic_server_config = QuicServerConfig::with_initial(
            Arc::new(rustls_config),
            TLS13_AES_128_GCM_SHA256
                .tls13()
                .ok_or_else(|| Error::new(ErrorKind::Other, "Failed to get TLS 1.3 cipher suite"))?
                .quic_suite()
                .ok_or_else(|| Error::new(ErrorKind::Other, "Failed to get QUIC cipher suite"))?,
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Failed to create QUIC server config: {}", e),
            )
        })?;

        let mut config = ServerConfig::with_crypto(Arc::new(quic_server_config));

        let transport_config = {
            let mut tc = TransportConfig::default();
            tc.max_concurrent_bidi_streams(VarInt::from_u32(512))
                .max_concurrent_uni_streams(VarInt::from_u32(512))
                .stream_receive_window(VarInt::from_u32(4 * 1024 * 1024))
                .receive_window(VarInt::from_u32(32 * 1024 * 1024))
                .send_window(64 * 1024 * 1024)
                .keep_alive_interval(Some(Duration::from_secs(10)))
                .congestion_controller_factory(Arc::new(BbrConfig::default()))
                .max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("Invalid idle timeout: {}", e),
                    )
                })?));
            tc
        };

        config.transport_config(Arc::new(transport_config));

        let socket = {
            let domain = match self.socket {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };

            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| {
                Error::new(ErrorKind::Other, format!("Failed to create socket: {}", e))
            })?;

            if Domain::IPV6 == domain {
                socket.set_only_v6(false).map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("Failed to set IPv6 only mode: {}", e),
                    )
                })?;
            }
            socket.set_reuse_address(true)?;
            #[cfg(unix)]
            socket.set_reuse_port(true)?;

            #[cfg(target_os = "linux")]
            socket.set_recv_tos(true)?;
            #[cfg(target_os = "linux")]
            socket.set_tos(184)?;

            socket.set_recv_buffer_size(1 << 25)?;
            socket.set_send_buffer_size(1 << 25)?;
            socket.set_nonblocking(true)?;
            socket.bind(&SockAddr::from(self.socket)).map_err(|e| {
                Error::new(ErrorKind::Other, format!("Failed to bind socket: {}", e))
            })?;

            std::net::UdpSocket::from(socket)
        };

        let ep = Endpoint::new(
            EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(TokioRuntime),
        )?;
        self.ep = Some(ep);
        self.status = ServerStatus::Running(Instant::now());
        Ok(Instant::now())
    }

    async fn start(&mut self) -> Result<Instant, Error> {
        let status = self.status().await?;

        match status {
            ServerStatus::Initializing(_) => {
                Err(Error::new(ErrorKind::Other, "Server is still initializing"))
            }
            ServerStatus::Running(_) => {
                let ep = if let Some(ep) = &self.ep {
                    let addr = ep.local_addr().map_err(|e| {
                        Error::new(
                            ErrorKind::Other,
                            format!("Failed to get local address: {}", e),
                        )
                    })?;
                    info!("Starting TUIC server on {}", addr);
                    ep
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "Need to initialize EndPoint first, call init() method",
                    ));
                };

                let tuic_processor = Arc::clone(&self.processor);
                let mut shutdown_rx = self.shutdown_rx.as_mut().cloned();

                loop {
                    tokio::select! {
                        incoming = ep.accept() => {
                            let incoming = match incoming {
                                Some(conn) => conn,
                                None => {
                                    debug!("Endpoint incoming stream closed!");
                                    continue;
                                }
                            };

                            let tuic_processor = Arc::clone(&tuic_processor);
                            tokio::spawn(async move {
                                match incoming.accept() {
                                    Ok(connecting) => match connecting.await {
                                        Ok(connection) => {
                                            let remote = connection.remote_address();
                                            let notifier = Arc::new(OneShotNotifier::new());

                                            let t_notifier = Arc::clone(&notifier);
                                            let recevied_processor = Arc::clone(&tuic_processor);
                                            let recevied_conn = connection.clone();
                                            let t_uni = tokio::spawn(async move {
                                                let _ = recevied_processor
                                                    .process_uni(recevied_conn, t_notifier)
                                                    .await;
                                            });

                                            let bidirectional_processor = Arc::clone(&tuic_processor);
                                            let bidirection_conn = connection.clone();
                                            let rx = notifier.clone();
                                            let t_bid = tokio::spawn(async move {
                                                if let Some(state) = rx.wait().await {
                                                    match state {
                                                        NotifyState::Success => {
                                                            let _ = bidirectional_processor
                                                                .process_bidirectional(bidirection_conn)
                                                                .await;
                                                        }
                                                        NotifyState::Failure => {
                                                            debug!("Do authentication failed, client: {}", remote);
                                                            return;
                                                        }
                                                    }
                                                }
                                            });

                                            let datagram_processor = Arc::clone(&tuic_processor);
                                            let datagram_conn = connection.clone();
                                            let rx = notifier.clone();
                                            let t_dat = tokio::spawn(async move {
                                                if let Some(state) = rx.wait().await {
                                                    match state {
                                                        NotifyState::Success => {
                                                            let _ = datagram_processor
                                                                .process_datagram(datagram_conn)
                                                                .await;
                                                        }
                                                        NotifyState::Failure => {
                                                            debug!("Do authentication failed, client: {}", remote);
                                                            return;
                                                        }
                                                    }
                                                }
                                            });

                                            let _ = tokio::join!(t_uni, t_bid, t_dat);
                                            debug!("Connection with {} has finished!", remote);
                                        }
                                        Err(e) => {
                                            debug!("Connecting await failed: {}", e);
                                        }
                                    },
                                    Err(e) => {
                                        debug!("Incoming.accept() failed: {}", e);
                                    }
                                }
                            });
                        }
                        _ = async {
                            if let Some(rx) = &mut shutdown_rx {
                                let _ = rx.changed().await;
                            }
                        } => {
                            info!("TUIC server received shutdown signal, breaking main loop");
                            return Ok(Instant::now());
                        }
                    }
                }
            }
            ServerStatus::Stopped(instant) => Err(Error::new(
                ErrorKind::Other,
                format!("Cannot start: server was stopped at {:?}", instant),
            )),
        }
    }

    async fn stop(&mut self) -> Result<Instant, Error> {
        match self.status {
            ServerStatus::Running(_) => {
                info!("Stopping TUIC server that was running");
                self.status = ServerStatus::Stopped(Instant::now());

                if let Some(ep) = &self.ep {
                    ep.close(0u32.into(), b"Server shutdown");
                    info!("TUIC endpoint closed");
                }
                Ok(Instant::now())
            }
            ServerStatus::Initializing(_) => Err(Error::new(
                ErrorKind::Other,
                "Cannot stop: server is still initializing",
            )),
            ServerStatus::Stopped(instant) => Err(Error::new(
                ErrorKind::Other,
                format!("Server is already stopped at {:?}", instant),
            )),
        }
    }

    async fn status(&mut self) -> Result<&ServerStatus, Error> {
        Ok(&self.status)
    }
}
