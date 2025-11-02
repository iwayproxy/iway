use async_trait::async_trait;
use tracing::debug;
use quinn::Connection;
use std::sync::Arc;

use anyhow::Result;

use crate::{
    processor::tuic::udp_session_manager::UdpSessionManager,
    protocol::tuic::command::dissociate::Dissociate,
};

use super::Processor;

pub struct DissociateProcess {
    connection: Connection,
    dissociate: Dissociate,
    udp_session_manager: Arc<UdpSessionManager>,
}

impl DissociateProcess {
    pub fn new(
        connection: Connection,
        dissociate: Dissociate,
        udp_session_manager: Arc<UdpSessionManager>,
    ) -> Self {
        Self {
            connection,
            dissociate,
            udp_session_manager,
        }
    }
}

#[async_trait]
impl Processor for DissociateProcess {
    async fn process(&mut self) -> Result<()> {
        debug!(
            "Processing dissociate : {:?} from {}",
            self.dissociate,
            self.dissociate.assoc_id()
        );
        self.udp_session_manager
            .remove_session(self.connection.remote_address(), self.dissociate.assoc_id());
        Ok(())
    }
}
