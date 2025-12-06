use std::sync::Arc;

use anyhow::{Result, bail};
use async_trait::async_trait;
use quinn::Connection;
use tracing::debug;

use crate::{
    processor::tuic::{CommandProcessor, context::RuntimeContext},
    protocol::tuic::command::Command,
};

pub struct HeartbeatProcessor {}

#[async_trait]
impl CommandProcessor for HeartbeatProcessor {
    async fn process(
        &self,
        context: Arc<RuntimeContext>,
        connection: Connection,
        command: Option<Command>,
    ) -> Result<bool> {
        context.wait_for_auth().await;

        let heartbeat = match command {
            Some(Command::Heartbeat(heartbeat)) => heartbeat,
            _ => {
                bail!("This must not happen! command: {:?}", command)
            }
        };

        debug!(
            "Processing heartbeat : {:?} from {}",
            &heartbeat,
            &connection.remote_address()
        );
        Ok(true)
    }
}
