use std::{
    fmt::Debug,
    io::{Error, ErrorKind},
    sync::Arc,
};

use dashmap::DashMap;
use tracing::error;
use uuid::Uuid;

use crate::authenticate::AuthenticationConnection;
use crate::protocol::tuic::command::authenticate::Authenticate;

#[derive(Debug)]
pub struct TuicAuthenticationManager {
    users: Arc<DashMap<Uuid, Box<[u8]>>>,
    // Track failed attempts per UUID
    failed_attempts: Arc<DashMap<Uuid, FailedAttempts>>,
}

/// Track authentication failures with timestamp for auto-reset
#[derive(Debug)]
struct FailedAttempts {
    count: u32,
    first_failure: std::time::Instant,
}

impl FailedAttempts {
    fn new() -> Self {
        Self {
            count: 1,
            first_failure: std::time::Instant::now(),
        }
    }

    fn increment(&mut self) -> u32 {
        // If too old, reset counter
        if self.first_failure.elapsed() > std::time::Duration::from_secs(3600) {
            self.count = 0;
            self.first_failure = std::time::Instant::now();
        }
        self.count += 1;
        self.count
    }
}

impl TuicAuthenticationManager {
    // Maximum failed attempts within the time window
    const MAX_FAILED_ATTEMPTS: u32 = 5;

    pub fn new<I>(user_entries: I) -> Self
    where
        I: IntoIterator<Item = (Uuid, String)>,
    {
        let users: Arc<DashMap<Uuid, Box<[u8]>>> = Arc::new(DashMap::new());
        let failed_attempts: Arc<DashMap<Uuid, FailedAttempts>> = Arc::new(DashMap::new());

        for (uuid, password) in user_entries {
            users.insert(uuid, Box::from(password.as_bytes()));
        }

        TuicAuthenticationManager {
            users,
            failed_attempts,
        }
    }

    pub async fn authenticate(
        &self,
        authenticate: Authenticate,
        connection: &impl AuthenticationConnection,
    ) -> Result<(), Error> {
        let mut buf: [u8; 32] = [0; 32];
        let password = match self.users.get(&authenticate.uuid()) {
            Some(password) => password,
            None => {
                error!(
                    "Failed to authenticate (user not found) uuid={} from={} ",
                    authenticate.uuid(),
                    connection.remote_address()
                );
                return Err(Error::new(ErrorKind::Other, "User not found"));
            }
        };

        if let Err(e) = connection
            .export_keying_material(&mut buf, authenticate.uuid().as_bytes(), &password)
            .await
        {
            error!(
                "Failed to export keying material for uuid={} from={} err={:?}",
                authenticate.uuid(),
                connection.remote_address(),
                e
            );
            return Err(Error::new(ErrorKind::Other, "Failed to derive token"));
        }

        // First check if this UUID is rate limited
        let uuid = authenticate.uuid();
        if let Some(mut attempts) = self.failed_attempts.get_mut(&uuid) {
            if attempts.count >= Self::MAX_FAILED_ATTEMPTS {
                // Check if we should reset based on time elapsed (1 hour window)
                if attempts.first_failure.elapsed() <= std::time::Duration::from_secs(3600) {
                    error!(
                        "Too many failed attempts for uuid={} from={} attempts={}",
                        uuid,
                        connection.remote_address(),
                        attempts.count
                    );
                    return Err(Error::new(ErrorKind::Other, "Too many failed attempts"));
                }
                // Reset counter if time window passed
                attempts.count = 0;
                attempts.first_failure = std::time::Instant::now();
            }
        }

        if authenticate.verify_token(&buf) {
            // On success, remove failed attempts record
            self.failed_attempts.remove(&uuid);
            Ok(())
        } else {
            // Increment or initialize failed attempts counter
            let count = match self.failed_attempts.get_mut(&uuid) {
                Some(mut attempts) => attempts.increment(),
                None => {
                    self.failed_attempts.insert(uuid, FailedAttempts::new());
                    1
                }
            };

            error!(
                "Unauthenticated access from={} uuid={} (token mismatch, attempt {}/{})",
                connection.remote_address(),
                uuid,
                count,
                Self::MAX_FAILED_ATTEMPTS
            );
            Err(Error::new(ErrorKind::Other, "Unauthenticated access"))
        }
    }
}
