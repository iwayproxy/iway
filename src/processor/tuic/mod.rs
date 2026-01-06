pub mod command;

pub mod context;
pub mod notifier;
pub mod session;

use anyhow::Result;
use async_trait::async_trait;
use std::io::Cursor;
use std::sync::Arc;
use uuid::Uuid;

use quinn::Connection;
use tracing::debug;

use crate::authenticate::tuic::TuicAuthenticationManager;
use crate::processor::tuic::command::CommandUniprocessor;
use crate::processor::tuic::context::RuntimeContext;
use crate::protocol::tuic::command::Command;

pub struct TuicConnectionProcessor {
    command_processor: Arc<CommandUniprocessor>,
}

impl TuicConnectionProcessor {
    pub async fn process_uni(
        &self,
        context: Arc<RuntimeContext>,
        connection: Arc<Connection>,
    ) -> Result<()> {
        loop {
            let connection = Arc::clone(&connection);

            let recv_stream = match connection.accept_uni().await {
                Ok(recv_stream) => recv_stream,
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    break;
                }
                Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                    break;
                }
                Err(e) => {
                    debug!("Failed to accept unidirectional stream: {}", e);
                    break;
                }
            };

            let Ok(command) = Command::read_from(recv_stream).await else {
                debug!("Failed to read command from unidirectional stream");
                break;
            };

            let context = Arc::clone(&context);
            let command_processor = Arc::clone(&self.command_processor);

            tokio::spawn(async move {
                let _ = command_processor
                    .process(context, Arc::clone(&connection), Some(command))
                    .await;
            });
        }

        Ok(())
    }

    pub async fn process_bidirectional(
        &self,
        context: Arc<RuntimeContext>,
        connection: Arc<Connection>,
    ) -> Result<()> {
        let command_processor = self.command_processor.clone();
        tokio::spawn(async move {
            if let Err(e) = command_processor
                .process(context, Arc::clone(&connection), None)
                .await
            {
                debug!("Failed to process Connect command: {}", e);
            }
        });

        Ok(())
    }

    pub async fn process_datagram(
        &self,
        context: Arc<RuntimeContext>,
        connection: Arc<Connection>,
    ) -> Result<()> {
        while let Ok(bytes) = connection.read_datagram().await {
            let context = Arc::clone(&context);
            let cursor = Cursor::new(&bytes);

            let Ok(command) = Command::read_from(cursor).await else {
                debug!("Failed to read command from unidirectional stream");
                break;
            };

            let command_processor = Arc::clone(&self.command_processor);
            let connection = Arc::clone(&connection);
            tokio::spawn(async move {
                let _ = command_processor
                    .process(context, Arc::clone(&connection), Some(command))
                    .await;
            });
        }

        Ok(())
    }

    pub fn new<I>(user_entries: I) -> Self
    where
        I: IntoIterator<Item = (Uuid, Arc<[u8]>)>,
    {
        let authentication_manager = TuicAuthenticationManager::new(user_entries);

        let command_processor = Arc::new(CommandUniprocessor::new(authentication_manager));

        Self { command_processor }
    }
}

#[async_trait]
pub trait CommandProcessor {
    async fn process(
        &self,
        context: Arc<RuntimeContext>,
        connection: Arc<Connection>,
        command: Option<Command>,
    ) -> Result<bool>;
}
