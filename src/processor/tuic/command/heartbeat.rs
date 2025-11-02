use anyhow::Result;
use async_trait::async_trait;
use tracing::debug;
use quinn::Connection;
use std::sync::Arc;

use crate::protocol::tuic::command::heartbeat::Heartbeat;

use super::Processor;

pub struct HeartbeatProcessor {
    heartbeat: Heartbeat,
    connection: Arc<Connection>,
}

impl HeartbeatProcessor {
    pub fn new(heartbeat: Heartbeat, connection: Arc<Connection>) -> Self {
        Self {
            heartbeat,
            connection,
        }
    }
}

#[async_trait]
impl Processor for HeartbeatProcessor {
    async fn process(&mut self) -> Result<()> {
        debug!(
            "Processing heartbeat : {:?} from {}",
            self.heartbeat,
            self.connection.remote_address()
        );
        Ok(())
    }
}
