use async_trait::async_trait;
use quinn::Connection;
use std::sync::Arc;
use tracing::debug;

use anyhow::{Result, bail};

use crate::{
    processor::tuic::{CommandProcessor, context::RuntimeContext},
    protocol::tuic::command::Command,
};

pub struct DissociateProcess {}

#[async_trait]
impl CommandProcessor for DissociateProcess {
    async fn process(
        &self,
        context: Arc<RuntimeContext>,
        connection: Connection,
        command: Option<Command>,
    ) -> Result<bool> {
        context.wait_for_auth().await;

        let dissociate = if let Some(Command::Dissociate(dissociated)) = command {
            dissociated
        } else {
            bail!("This must not happen! command: {:?}", command)
        };

        debug!(
            "Processing dissociate : {:?} from {}",
            &dissociate,
            &connection.remote_address()
        );

        let _ = context.remove_session(dissociate.assoc_id());
        Ok(true)
    }
}
