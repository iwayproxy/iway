use std::sync::Arc;

use anyhow::{Result, bail};

use async_trait::async_trait;
use quinn::Connection;

use crate::{
    authenticate::tuic::TuicAuthenticationManager,
    processor::tuic::{CommandProcessor, context::RuntimeContext},
    protocol::tuic::command::Command,
};

pub struct AuthenticateProcessor {
    authenticate_manager: TuicAuthenticationManager,
}

#[async_trait]
impl CommandProcessor for AuthenticateProcessor {
    async fn process(
        &self,
        context: Arc<RuntimeContext>,
        connection: Arc<Connection>,
        command: Option<Command>,
    ) -> Result<bool> {
        let authenticate = if let Some(Command::Authenticate(authenticate)) = command {
            authenticate
        } else {
            bail!("This must not happen! command: {:?}", command)
        };

        let password = match self.authenticate_manager.password(authenticate.uuid()) {
            Ok(value) => value,
            Err(_) => {
                bail!(
                    "Failed to authencate client: {}, uuid: {} is not existed:",
                    &connection.remote_address(),
                    &authenticate.uuid()
                );
            }
        };

        let mut buff: [u8; 32] = [0; 32];
        if let Err(e) =
            &connection.export_keying_material(&mut buff, authenticate.uuid().as_bytes(), &password)
        {
            bail!(
                "Failed to export keying material for uuid={} from={} err={:?}",
                &authenticate.uuid(),
                &connection.remote_address(),
                e
            );
        }

        match authenticate.verify_token(&buff) {
            Ok(true) => {
                context.auth_done(true).await;
                Ok(true)
            }
            _ => {
                context.auth_done(false).await;
                bail!(
                    "Failed to verify client token! client: {}, uuid: {}",
                    &connection.remote_address(),
                    &authenticate.uuid()
                )
            }
        }
    }
}

impl AuthenticateProcessor {
    pub fn new(authenticate_manager: TuicAuthenticationManager) -> Self {
        Self {
            authenticate_manager,
        }
    }
}
