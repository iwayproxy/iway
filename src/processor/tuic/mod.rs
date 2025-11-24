pub mod command;
pub mod udp_session_manager;

use anyhow::Context;
use command::dissociate::DissociateProcess;
use std::io::{self, Cursor};
use std::sync::Arc;
use std::time::Duration;
use udp_session_manager::UdpSessionManager;
use uuid::Uuid;

use async_trait::async_trait;
use command::OneShotNotifier;
use command::connect::ConnectProcessor;
use command::heartbeat::HeartbeatProcessor;

use quinn::{Connection, VarInt};
use tracing::{debug, error, info};

use crate::authenticate::tuic::TuicAuthenticationManager;
use crate::processor::ConnectionProcessor;
use crate::processor::tuic::command::authenticate::AuthenticateProcessor;
use crate::protocol::tuic::command::Command;
use command::packet::PacketProcessor;

// #[derive(Debug)]
pub struct TuicConnectionProcessor {
    authenticate_processor: Arc<AuthenticateProcessor>,
    connect_processor: Arc<ConnectProcessor>,
    dissociate_processor: Arc<DissociateProcess>,
    heartbeat_processor: Arc<HeartbeatProcessor>,
    packet_processor: Arc<PacketProcessor>,
}

#[async_trait]
impl ConnectionProcessor for TuicConnectionProcessor {
    async fn process_uni(
        &self,
        connection: Connection,
        notifier: Arc<OneShotNotifier>,
    ) -> io::Result<()> {
        loop {
            let recv_stream = match connection.accept_uni().await {
                Ok(recv_stream) => recv_stream,
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    break;
                }
                Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                    break;
                }
                Err(e) => {
                    debug!("Failed to accept unidirectional stream: {}", e);
                    break;
                }
            };

            let Ok(command) = Command::read_from(recv_stream).await else {
                debug!("Failed to read command from unidirectional stream");
                break;
            };

            match command {
                Command::Authenticate(authenticate) => {
                    match self
                        .authenticate_processor
                        .verify(authenticate, connection.clone())
                    {
                        Ok(_) => {
                            debug!(
                                "Successful to authenticate client, address: {}",
                                &connection.remote_address()
                            );
                            notifier.notify(true);
                        }
                        Err(e) => {
                            info!("Failed to authenticate: {}", e);
                            notifier.notify(false);
                            continue;
                        }
                    }
                }

                Command::Packet(packet) => {
                    let rx = Arc::clone(&notifier);
                    if let Some(state) = rx.wait().await {
                        match state {
                            true => {
                                debug!("Received packet from {}", &connection.remote_address());
                                let packet_processor = Arc::clone(&self.packet_processor);
                                let connection = connection.clone();

                                tokio::spawn(async move {
                                    match packet_processor
                                        .process(connection, packet)
                                        .await
                                        .context("Failed to handle packet from uni-stream.")
                                    {
                                        Ok(_) => {
                                            debug!("Success to process packet from uni-stream")
                                        }
                                        Err(_) => {
                                            debug!("Failed to process packet from uni-stream")
                                        }
                                    }
                                });
                            }
                            false => {
                                debug!(
                                    "Do authentication failed, client: {}",
                                    &connection.remote_address()
                                );
                                continue;
                            }
                        }
                    }
                }

                Command::Dissociate(dissociate) => {
                    let rx = Arc::clone(&notifier);
                    if let Some(state) = rx.wait().await {
                        match state {
                            true => {
                                debug!(
                                    "Received dissociate from {} dissociate:{}",
                                    &connection.remote_address(),
                                    dissociate
                                );
                                let connection = connection.clone();
                                let dissociate_processor = Arc::clone(&self.dissociate_processor);
                                tokio::spawn(async move {
                                    let _ =
                                        dissociate_processor.process(connection, dissociate).await;
                                });
                            }
                            false => {
                                debug!(
                                    "Do authentication failed, client: {}",
                                    &connection.remote_address()
                                );
                                continue;
                            }
                        }
                    }
                }
                _ => {
                    debug!(
                        "process_recevied: Command {} sent via wrong channal!",
                        command
                    );
                    continue;
                }
            }
        }
        Ok(())
    }

    async fn process_bidirectional(&self, connection: Connection) -> io::Result<()> {
        while let Ok((send, mut recv)) = connection.accept_bi().await {
            let connection = connection.clone();
            let connect_processor = Arc::clone(&self.connect_processor);

            let processing = async move {
                let command = match Command::read_from(&mut recv).await {
                    Ok(command) => command,
                    Err(e) => {
                        debug!(
                            "Failed to parse command from {} E: {}",
                            &connection.remote_address(),
                            e
                        );
                        for (i, cause) in e.chain().enumerate() {
                            debug!("{}: {}", i, cause);
                        }
                        return;
                    }
                };
                match command {
                    Command::Connect(connect) => {
                        tokio::spawn(async move {
                            if let Err(e) = connect_processor.process(send, recv, connect).await {
                                debug!("Failed to process Connect command: {}", e);
                            }
                        });
                    }
                    _ => {
                        tokio::spawn(async move {
                            error!("Received unexpected command type: {}", &command);
                            connection.close(
                                VarInt::from_u32(0xffff),
                                b"Received unexpected command type!",
                            );
                        });
                    }
                };
            };

            tokio::spawn(processing);
        }

        Ok(())
    }

    async fn process_datagram(&self, connection: Connection) -> io::Result<()> {
        while let Ok(bytes) = connection.read_datagram().await {
            let mut cursor = Cursor::new(&bytes);
            match Command::read_from(&mut cursor).await {
                Ok(Command::Packet(packet)) => {
                    let connection = connection.clone();
                    let packet_processor = Arc::clone(&self.packet_processor);
                    tokio::spawn(async move {
                        if let Err(e) = packet_processor.process(connection, packet).await {
                            debug!("Failed to process datagram packet: {}", e);
                        }
                    });
                }

                Ok(Command::Heartbeat(heartbeat)) => {
                    let connection = connection.clone();
                    let heartbeat_processor = Arc::clone(&self.heartbeat_processor);
                    tokio::spawn(async move {
                        if let Err(e) = heartbeat_processor.process(heartbeat, connection).await {
                            debug!("Failed to process datagram heartbeat: {}", e);
                        }
                    });
                }

                Ok(command) => {
                    debug!(
                        "Received unexpected command type via datagram: {}",
                        &command
                    );
                }
                Err(e) => {
                    debug!("Failed to parse datagram command: {}", e);
                }
            }
        }

        Ok(())
    }
}

impl TuicConnectionProcessor {
    /// Create a new TuicConnectionProcessor.
    ///
    /// - `user_entries`: iterator of (Uuid, password)
    /// - `udp_session_timeout`: per-session reassembly timeout
    /// - `udp_cleanup_interval`: periodic cleanup interval
    /// - `max_sessions`: optional cap for concurrent UDP sessions
    /// - `max_reassembly_bytes_per_session`: optional cap for reassembly bytes per session
    pub fn new<I>(
        user_entries: I,
        udp_session_timeout: Duration,
        udp_cleanup_interval: Duration,
        max_sessions: Option<usize>,
        max_reassembly_bytes_per_session: Option<usize>,
    ) -> Self
    where
        I: IntoIterator<Item = (Uuid, String)>,
    {
        //command processors
        let authentication_manager = TuicAuthenticationManager::new(user_entries);

        let authenticate_processor = Arc::new(AuthenticateProcessor::new(authentication_manager));

        let connection_processor = Arc::new(ConnectProcessor::new());

        let heartbeat_processor = Arc::new(HeartbeatProcessor::new());

        let udp_session_manager = UdpSessionManager::new(udp_session_timeout, udp_cleanup_interval);

        let packet_processor = Arc::new(PacketProcessor::new(Arc::clone(&udp_session_manager)));

        let dissociate_processor =
            Arc::new(DissociateProcess::new(Arc::clone(&udp_session_manager)));

        // apply optional limits
        udp_session_manager.set_max_sessions(max_sessions);

        udp_session_manager.set_max_reassembly_bytes_per_session(max_reassembly_bytes_per_session);

        Self {
            authenticate_processor,
            connect_processor: connection_processor,
            dissociate_processor,
            heartbeat_processor,
            packet_processor,
        }
    }
}
