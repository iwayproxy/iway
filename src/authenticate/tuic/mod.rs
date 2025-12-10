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
        I: IntoIterator<Item = (Uuid, Arc<[u8]>)>,
    {
        let users: Arc<DashMap<Uuid, Arc<[u8]>>> = Arc::new(DashMap::new());

        for (uuid, password_bytes) in user_entries {
            users.insert(uuid, password_bytes);
        }

        TuicAuthenticationManager { users }
    }

    pub fn password(&self, uuid: &Uuid) -> Result<Arc<[u8]>> {
        self.users
            .get(uuid)
            .map(|value| Arc::clone(&*value))
            .ok_or_else(|| anyhow!("Illegal UUID {} trys to access the server.", &uuid))
    }
}
