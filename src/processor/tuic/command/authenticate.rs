use std::sync::Arc;

use anyhow::{Ok, Result};

use quinn::Connection;

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

    pub fn verify(&self) -> Result<()>{

        Ok(())
    }
}

