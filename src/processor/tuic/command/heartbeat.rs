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
        let auth_result = context.wait_for_auth().await;
        if auth_result != Some(true) {
            bail!("Authentication failed or timed out");
        }

        let heartbeat = if let Some(Command::Heartbeat(heartbeath)) = command {
            heartbeath
        } else {
            bail!("This must not happen! command: {:?}", command)
        };

        debug!(
            "Processing heartbeat : {:?} from {}",
            &heartbeat,
            &connection.remote_address()
        );
        Ok(true)
    }
}
