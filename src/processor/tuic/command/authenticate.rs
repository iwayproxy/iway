use anyhow::Result;

use quinn::Connection;
use tracing::error;

use crate::{authenticate::{tuic::TuicAuthenticationManager}, protocol::tuic::command::authenticate::Authenticate};

pub struct AuthenticateProcessor {
    authenticate_manager :TuicAuthenticationManager,
}

impl AuthenticateProcessor {
    pub fn new(authenticate_manager: TuicAuthenticationManager) -> Self {
        Self { authenticate_manager }
    }

    pub fn verify(&self, authenticate :Authenticate, connection :Connection) -> Result<bool>{
        let password = match self.authenticate_manager.password(authenticate.uuid()) {
            Ok(value) => value,
            Err(_) => todo!(),
        };

        let mut buff :[u8; 32] = [0; 32];
        if let Err(e) = connection
            .export_keying_material(&mut buff, authenticate.uuid().as_bytes(), &password)
        {
            error!(
                "Failed to export keying material for uuid={} from={} err={:?}",
                authenticate.uuid(),
                connection.remote_address(),
                e
            );
            return Err(anyhow::anyhow!(""));
        }

        Ok(authenticate.verify_token(&buff))
    }
}
