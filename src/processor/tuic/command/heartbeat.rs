use anyhow::Result;
use tracing::debug;
use quinn::Connection;

use crate::protocol::tuic::command::heartbeat::Heartbeat;

pub struct HeartbeatProcessor {
    
}

impl HeartbeatProcessor {
    pub fn new() -> Self {
        Self {}
    }
    
    pub async fn process(&self, heartbeat: Heartbeat, connection: Connection) -> Result<()> {
        debug!(
            "Processing heartbeat : {:?} from {}",
            heartbeat,
            connection.remote_address()
        );
        Ok(())
    }
}
