pub mod command;
pub mod udp_session_manager;

use anyhow::Context;
use command::dissociate::DissociateProcess;
use std::io::{self, Cursor};
use std::sync::Arc;
use std::time::Duration;
use udp_session_manager::UdpSessionManager;

use async_trait::async_trait;
use command::connect::ConnectProcessor;
use command::heartbeat::HeartbeatProcessor;
use command::{NotifyState, OneShotNotifier};

use log::{debug, error};
use quinn::{Connection, VarInt};

use crate::authenticate::tuic::TuicAuthenticationManager;
use crate::processor::ConnectionProcessor;
use crate::processor::tuic::command::Processor;
use crate::protocol::tuic::command::command::Command;
use command::packet::PacketProcessor;

#[derive(Debug)]
pub struct TuicConnectionProcessor {
    authentication_manager: Arc<TuicAuthenticationManager>,
    udp_session_manager: Arc<UdpSessionManager>,
}

#[async_trait]
impl ConnectionProcessor for TuicConnectionProcessor {
    async fn process_uni(
        &self,
        connection: Connection,
        notifier: Arc<OneShotNotifier>,
    ) -> io::Result<()> {
        let remote = connection.remote_address();

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
                        .authentication_manager
                        .authenticate(authenticate, &connection)
                        .await
                    {
                        Ok(_) => {
                            debug!(
                                "Successful to authenticate client, address: {}",
                                connection.remote_address()
                            );
                            notifier.notify(NotifyState::Success).await;
                        }
                        Err(e) => {
                            debug!("Failed to authenticate: {}", e);
                            notifier.notify(NotifyState::Failure).await;
                            continue;
                        }
                    }
                }

                Command::Packet(packet) => {
                    let rx = notifier.clone();
                    if let Some(state) = rx.wait().await {
                        match state {
                            NotifyState::Success => {
                                debug!("Received packet from {}", connection.remote_address());
                                let udp_session_manager = Arc::clone(&self.udp_session_manager);
                                let connection = Arc::new(connection.clone());
                                tokio::spawn(async move {
                                    match PacketProcessor::new(
                                        packet,
                                        udp_session_manager,
                                        connection,
                                    )
                                    .process()
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
                            NotifyState::Failure => {
                                debug!("Do authentication failed, client: {}", remote);
                                continue;
                            }
                        }
                    }
                }

                Command::Dissociate(dissociate) => {
                    let rx = notifier.clone();
                    if let Some(state) = rx.wait().await {
                        match state {
                            NotifyState::Success => {
                                debug!(
                                    "Received dissociate from {} dissociate:{}",
                                    remote, dissociate
                                );
                                let connection = connection.clone();
                                let session_manager = Arc::clone(&self.udp_session_manager);
                                tokio::spawn(async move {
                                    let _ = DissociateProcess::new(
                                        connection,
                                        dissociate,
                                        session_manager,
                                    )
                                    .process()
                                    .await;
                                });
                            }
                            NotifyState::Failure => {
                                debug!("Do authentication failed, client: {}", remote);
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
        let connection = Arc::new(connection);
        while let Ok((send, mut recv)) = connection.accept_bi().await {
            let remote = connection.remote_address();
            let connection = connection.clone();

            let processing = async move {
                let command = match Command::read_from(&mut recv).await {
                    Ok(command) => command,
                    Err(e) => {
                        debug!("Failed to parse command from {} E: {}", remote, e);
                        for (i, cause) in e.chain().enumerate() {
                            debug!("{}: {}", i, cause);
                        }
                        return;
                    }
                };
                match command {
                    Command::Connect(connect) => {
                        tokio::spawn(async move {
                            if let Err(e) =
                                ConnectProcessor::new(send, recv, connect).process().await
                            {
                                debug!("Failed to process Connect command: {}", e);
                            }
                        });
                    }
                    _ => {
                        tokio::spawn(async move {
                            error!("Received unexpected command type: {}", command);
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
        let connection = Arc::new(connection);

        while let Ok(bytes) = connection.read_datagram().await {
            let mut cursor = Cursor::new(&bytes);
            match Command::read_from(&mut cursor).await {
                Ok(Command::Packet(packet)) => {
                    let connection = Arc::clone(&connection);
                    let udp_session_manager = Arc::clone(&self.udp_session_manager);
                    tokio::spawn(async move {
                        if let Err(e) =
                            PacketProcessor::new(packet, udp_session_manager, connection)
                                .process()
                                .await
                        {
                            debug!("Failed to process datagram packet: {}", e);
                        }
                    });
                }
                Ok(Command::Heartbeat(heartbeat)) => {
                    let connection = Arc::clone(&connection);
                    tokio::spawn(async move {
                        if let Err(e) = HeartbeatProcessor::new(heartbeat, connection)
                            .process()
                            .await
                        {
                            debug!("Failed to process datagram heartbeat: {}", e);
                        }
                    });
                }
                Ok(command) => {
                    debug!("Received unexpected command type via datagram: {}", command);
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
    pub fn new<I>(user_entries: I) -> Self
    where
        I: IntoIterator<Item = (uuid::Uuid, String)>,
    {
        let authentication_manager = Arc::new(TuicAuthenticationManager::new(user_entries));
        let udp_session_manager =
            UdpSessionManager::new(Duration::from_secs(10), Duration::from_secs(30));

        Self {
            authentication_manager,
            udp_session_manager,
        }
    }
}
