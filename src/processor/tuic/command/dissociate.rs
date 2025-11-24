use quinn::Connection;
use std::sync::Arc;
use tracing::debug;

use anyhow::Result;

use crate::{
    processor::tuic::udp_session_manager::UdpSessionManager,
    protocol::tuic::command::dissociate::Dissociate,
};

pub struct DissociateProcess {
    udp_session_manager: Arc<UdpSessionManager>,
}

impl DissociateProcess {
    pub fn new(udp_session_manager: Arc<UdpSessionManager>) -> Self {
        Self {
            udp_session_manager,
        }
    }

    pub async fn process(&self, connection: Connection, dissociate: Dissociate) -> Result<()> {
        debug!(
            "Processing dissociate : {:?} from {}",
            &dissociate,
            &dissociate.assoc_id()
        );
        self.udp_session_manager
            .remove_session((&connection).remote_address(), (&dissociate).assoc_id());
        Ok(())
    }
}
