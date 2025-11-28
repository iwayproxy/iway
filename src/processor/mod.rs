use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use quinn::Connection;
use tuic::command::OneShotNotifier;

pub mod tuic;

#[async_trait]
pub trait ConnectionProcessor: Send + Sync {
    async fn process_uni(
        &self,
        connection: Connection,
        notifier: Arc<OneShotNotifier>,
    ) -> Result<()>;

    async fn process_bidirectional(&self, connection: Connection) -> Result<()>;

    async fn process_datagram(&self, connection: Connection) -> Result<()>;
}
