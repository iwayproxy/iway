use std::{
    fmt::Debug,
    io::{Error, ErrorKind},
    sync::Arc,
};

use dashmap::DashMap;
use log::error;
use quinn::Connection;

use uuid::Uuid;

use crate::protocol::tuic::command::authenticate::Authenticate;

#[derive(Debug)]
pub struct TuicAuthenticationManager {
    users: Arc<DashMap<Uuid, Box<[u8]>>>,
}

impl TuicAuthenticationManager {
    pub fn new<I>(user_entries: I) -> Self
    where
        I: IntoIterator<Item = (Uuid, String)>,
    {
        let users: Arc<DashMap<Uuid, Box<[u8]>>> = Arc::new(DashMap::new());

        for (uuid, password) in user_entries {
            users.insert(uuid, Box::from(password.as_bytes()));
        }

        TuicAuthenticationManager { users }
    }

    pub fn authenticate(
        &self,
        authenticate: Authenticate,
        connection: Connection,
    ) -> Result<(), Error> {
        let mut buf: [u8; 32] = [0; 32];
        let password = match self.users.get(&authenticate.uuid()) {
            Some(password) => password,
            None => {
                error!(
                    "Failed to authenticate, user not found: {}",
                    authenticate.uuid()
                );
                return Err(Error::new(ErrorKind::Other, "User not found"));
            }
        };

        connection
            .export_keying_material(&mut buf, authenticate.uuid().as_bytes(), &password)
            .unwrap();

        if authenticate.token() == buf {
            Ok(())
        } else {
            error!(
                "Unathenticated access from {} {:?}",
                connection.remote_address(),
                authenticate.token()
            );
            Err(Error::new(ErrorKind::Other, "Unathenticated access"))
        }
    }
}
