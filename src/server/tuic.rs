use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use std::{net::SocketAddr, path::Path, time::Instant};

use crate::processor::tuic::TuicConnectionProcessor;
use crate::processor::tuic::context::RuntimeContext;
use crate::processor::tuic::notifier::OneShotNotifier;

use super::{Server, ServerStatus};

use anyhow::{Context, Error, Result, anyhow, bail};
use async_trait::async_trait;
use quinn::congestion::BbrConfig;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig, VarInt};
use rustls::CipherSuite;
use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;
use rustls::crypto::{self, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::sync::watch::Receiver;
use tracing::{debug, info};

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("Failed to read certificate file: {:?}", path))?
        .collect::<std::result::Result<Vec<CertificateDer<'static>>, _>>()
        .with_context(|| "Failed to parse certificates!")?;

    if certs.is_empty() {
        bail!("No certificates found in file");
    }

    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key = PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("Failed to read private key file: {:?}", path))?;
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
    name: &'static str,
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
        let socket = config
            .server_addr()
            .parse()
            .with_context(|| "Failed to parse server adress with error")?;

        let user_entries = config
            .users()
            .iter()
            .filter_map(|u| {
                uuid::Uuid::parse_str(u.uuid())
                    .ok()
                    .map(|id| (id, Arc::from(u.password().as_bytes())))
            })
            .collect::<Vec<_>>();

        let processor = Arc::new(TuicConnectionProcessor::new(user_entries));

        Ok(Self {
            name: "TUIC v5",
            socket,
            ep: None,
            status: ServerStatus::Initializing(Instant::now()),
            processor,
            cert_path: PathBuf::from(config.cert_path()),
            key_path: PathBuf::from(config.key_path()),
            shutdown_rx,
        })
    }
}

#[async_trait]
impl Server for TuicServer {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn init(&mut self) -> Result<Instant, Error> {
        let certs = load_certs(&self.cert_path)?;
        let key = load_key(&self.key_path)?;

        let mut rustls_config =
            rustls::ServerConfig::builder_with_provider(CRYPTO_PROVIDER.clone())
                .with_protocol_versions(TLS_PROTOCOL_VERSIONS)
                .with_context(|| "Failed to set TLS protocol versions!")?
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .with_context(|| "Failed to configure TLS certificate!")?;

        rustls_config.alpn_protocols = vec![b"h3".to_vec()];
        rustls_config.max_early_data_size = u32::MAX;
        rustls_config.send_half_rtt_data = true;

        let quic_server_config = QuicServerConfig::with_initial(
            Arc::new(rustls_config),
            TLS13_AES_128_GCM_SHA256
                .tls13()
                .ok_or_else(|| anyhow!("Failed to get TLS 1.3 cipher suite"))?
                .quic_suite()
                .ok_or_else(|| anyhow!("Failed to get QUIC cipher suite"))?,
        )
        .with_context(|| "Failed to create QUIC server config!")?;

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
                .max_idle_timeout(Some(
                    Duration::from_secs(30)
                        .try_into()
                        .with_context(|| "Invalid idle timeout!")?,
                ));
            tc
        };

        config.transport_config(Arc::new(transport_config));

        let socket = {
            let domain = match self.socket {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };

            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                .with_context(|| format!("Failed to create socket: {:?}!", domain))?;

            if Domain::IPV6 == domain {
                socket
                    .set_only_v6(false)
                    .with_context(|| "Failed to set IPv6 only mode!")?;
            }
            socket.set_reuse_address(true)?;
            #[cfg(unix)]
            socket.set_reuse_port(true)?;

            #[cfg(target_os = "linux")]
            {
                use libc::{IP_TOS, IPPROTO_IP};
                use std::os::unix::prelude::AsRawFd;
                // Set IP_TOS to 0x10 (low delay)
                unsafe {
                    let tos: libc::c_int = 0x10;
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        IPPROTO_IP,
                        IP_TOS,
                        &tos as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&tos) as libc::socklen_t,
                    );
                }
            }

            socket.set_recv_buffer_size(1 << 25)?;
            socket.set_send_buffer_size(1 << 25)?;
            socket.set_nonblocking(true)?;
            socket
                .bind(&SockAddr::from(self.socket))
                .with_context(|| format!("Failed to bind socket: {}", self.socket))?;

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
                bail!("Server is still initializing");
            }
            ServerStatus::Running(_) => {
                let ep = if let Some(ep) = &self.ep {
                    let addr = ep
                        .local_addr()
                        .with_context(|| "Failed to get local address")?;
                    info!("Starting TUIC server on {}", addr);
                    ep
                } else {
                    bail!("Need to initialize EndPoint first, call init() method",);
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
                                            let context = Arc::new(RuntimeContext::new(OneShotNotifier::default()));

                                            debug!("New connection connected (ID: {})", &connection.stable_id());

                                            let recevied_processor = Arc::clone(&tuic_processor);
                                            let recevied_conn = connection.clone();
                                            let recevied_context = Arc::clone(&context);

                                            let t_uni = tokio::spawn(async move {
                                                let _ = recevied_processor
                                                    .process_uni(recevied_context, recevied_conn)
                                                    .await;
                                            });

                                            let bidirectional_processor = Arc::clone(&tuic_processor);
                                            let bidirection_conn = connection.clone();
                                            let bidiraction_context = Arc::clone(&context);
                                            let t_bid = tokio::spawn(async move {
                                                 let _ = bidirectional_processor
                                                                    .process_bidirectional(bidiraction_context, bidirection_conn)
                                                                    .await;
                                            });

                                            let datagram_processor = Arc::clone(&tuic_processor);
                                            let datagram_conn = connection.clone();
                                            let datagram_ontext = Arc::clone(&context);
                                            let t_dat = tokio::spawn(async move {
                                                let _ = datagram_processor
                                                                .process_datagram(datagram_ontext, datagram_conn)
                                                                .await;
                                            });

                                            let _ = tokio::join!(t_uni, t_bid, t_dat);
                                            debug!("The connection (ID:{}) was closed!", &connection.stable_id());
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
            ServerStatus::Stopped(instant) => {
                bail!("Cannot start: server was stopped at {:?}", instant)
            }
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
            ServerStatus::Initializing(_) => bail!("Cannot stop: server is still initializing",),
            ServerStatus::Stopped(instant) => bail!("Server is already stopped at {:?}", instant),
        }
    }

    async fn status(&mut self) -> Result<&ServerStatus, Error> {
        Ok(&self.status)
    }
}
