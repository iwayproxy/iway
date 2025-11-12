use anyhow::{Result, anyhow};
use std::{fmt::Debug, sync::Arc};

use dashmap::DashMap;
use uuid::Uuid;

#[derive(Debug)]
pub struct TuicAuthenticationManager {
    users: Arc<DashMap<Uuid, Arc<[u8]>>>,
}

impl TuicAuthenticationManager {
    pub fn new<I>(user_entries: I) -> Self
    where
        I: IntoIterator<Item = (Uuid, String)>,
    {
        let users: Arc<DashMap<Uuid, Arc<[u8]>>> = Arc::new(DashMap::new());

        for (uuid, password) in user_entries {
            let arc_bytes: Arc<[u8]> = Arc::from(password.into_bytes().into_boxed_slice());
            users.insert(uuid, arc_bytes);
        }

        TuicAuthenticationManager { users }
    }

    pub fn password(&self, uuid: &Uuid) -> Result<Arc<[u8]>> {
        match self.users.get(uuid) {
            Some(value) => Ok(value.clone()),
            None => Err(anyhow!("Illegal UUID {} trys to access the server.", uuid)),
        }
    }
}
