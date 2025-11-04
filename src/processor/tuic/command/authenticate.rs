use std::sync::Arc;

use anyhow::Result;

use quinn::Connection;
use tracing::error;

use crate::{authenticate::{tuic::TuicAuthenticationManager}, protocol::tuic::command::authenticate::Authenticate};

pub struct AuthenticateProcessor {
    authenticate :Authenticate,
    connection :Connection,
    authenticate_manager :Arc<TuicAuthenticationManager>,
}

impl AuthenticateProcessor {
    pub fn new(authenticate: Authenticate, connection: Connection, authenticate_manager: Arc<TuicAuthenticationManager>) -> Self {
        Self { authenticate, connection, authenticate_manager }
    }

    pub fn verify(&self) -> Result<bool>{
        let password = match self.authenticate_manager.password(self.authenticate.uuid()) {
            Ok(value) => value,
            Err(_) => todo!(),
        };

        let mut buff :[u8; 32] = [0; 32];
        if let Err(e) = self.connection
            .export_keying_material(&mut buff, self.authenticate.uuid().as_bytes(), &password)
        {
            error!(
                "Failed to export keying material for uuid={} from={} err={:?}",
                self.authenticate.uuid(),
                self.connection.remote_address(),
                e
            );
            return Err(anyhow::anyhow!(""));
        }

        Ok(self.authenticate.verify_token(&buff))
    }
}
