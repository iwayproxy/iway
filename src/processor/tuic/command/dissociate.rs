use async_trait::async_trait;
use quinn::Connection;
use std::sync::Arc;
use tracing::debug;

use anyhow::{Result, bail};

use crate::{
    processor::tuic::{
        CommandProcessor, context::RuntimeContext, udp_session_manager::UdpSessionManager,
    },
    protocol::tuic::command::Command,
};

pub struct DissociateProcess {
    udp_session_manager: Arc<UdpSessionManager>,
}

#[async_trait]
impl CommandProcessor for DissociateProcess {
    async fn process(
        &self,
        context: Arc<RuntimeContext>,
        connection: Connection,
        command: Option<Command>,
    ) -> Result<bool> {
        context.wait_for_auth().await;

        let dissociate = match command {
            Some(Command::Dissociate(dissociate)) => dissociate,
            _ => {
                bail!("This must not happen! command: {:?}", command)
            }
        };

        debug!(
            "Processing dissociate : {:?} from {}",
            &dissociate,
            &dissociate.assoc_id()
        );

        self.udp_session_manager
            .remove_session((&connection).remote_address(), (&dissociate).assoc_id());

        Ok(true)
    }
}

impl DissociateProcess {
    pub fn new(udp_session_manager: Arc<UdpSessionManager>) -> Self {
        Self {
            udp_session_manager,
        }
    }
}
