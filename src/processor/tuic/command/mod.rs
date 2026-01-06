pub mod authenticate;
pub mod connect;
pub mod dissociate;
pub mod heartbeat;
pub mod packet;

use std::sync::Arc;

use anyhow::{Result, bail};
use async_trait::async_trait;
use quinn::Connection;

use crate::authenticate::tuic::TuicAuthenticationManager;
use crate::processor::tuic::CommandProcessor;
use crate::processor::tuic::command::authenticate::AuthenticateProcessor;
use crate::processor::tuic::command::connect::ConnectProcessor;
use crate::processor::tuic::command::dissociate::DissociateProcess;
use crate::processor::tuic::command::heartbeat::HeartbeatProcessor;
use crate::processor::tuic::command::packet::PacketProcessor;
use crate::processor::tuic::context::RuntimeContext;
use crate::protocol::tuic::command::Command;

pub struct CommandUniprocessor {
    authenticate_processor: Arc<AuthenticateProcessor>,
    connect_processor: Arc<ConnectProcessor>,
    dissociate_processor: Arc<DissociateProcess>,
    heartbeat_processor: Arc<HeartbeatProcessor>,
    packet_processor: Arc<PacketProcessor>,
}

impl CommandUniprocessor {
    pub fn new(authentication_manager: TuicAuthenticationManager) -> Self {
        let authenticate_processor = Arc::new(AuthenticateProcessor::new(authentication_manager));

        let connect_processor = Arc::new(ConnectProcessor {});

        let heartbeat_processor = Arc::new(HeartbeatProcessor {});

        let packet_processor = Arc::new(PacketProcessor {});

        let dissociate_processor = Arc::new(DissociateProcess {});

        Self {
            authenticate_processor,
            connect_processor,
            dissociate_processor,
            heartbeat_processor,
            packet_processor,
        }
    }
}

#[async_trait]
impl CommandProcessor for CommandUniprocessor {
    async fn process(
        &self,
        context: Arc<RuntimeContext>,
        connection: Arc<Connection>,
        command: Option<Command>,
    ) -> Result<bool> {
        let command = match command {
            Some(command) => command,
            None => {
                self.connect_processor
                    .process(context, Arc::clone(&connection), None)
                    .await?;
                return Ok(true);
            }
        };

        match command {
            Command::Authenticate(_) => {
                self.authenticate_processor
                    .process(context, Arc::clone(&connection), Some(command))
                    .await?;
            }
            Command::Packet(_) => {
                self.packet_processor
                    .process(context, Arc::clone(&connection), Some(command))
                    .await?;
            }
            Command::Heartbeat(_) => {
                self.heartbeat_processor
                    .process(context, Arc::clone(&connection), Some(command))
                    .await?;
            }
            Command::Dissociate(_) => {
                self.dissociate_processor
                    .process(context, Arc::clone(&connection), Some(command))
                    .await?;
            }
            _ => bail!("This must not happen! command: {}", command),
        }

        Ok(true)
    }
}
