use std::sync::Arc;

use dashmap::DashMap;
use tracing::debug;

use crate::processor::tuic::{notifier::OneShotNotifier, session::UdpSession};

pub struct RuntimeContext {
    notifier: OneShotNotifier,
    udp_sessions: Arc<DashMap<u16, UdpSession>>,
}

impl RuntimeContext {
    pub fn new(notifier: OneShotNotifier) -> Self {
        Self {
            notifier,
            udp_sessions: Arc::new(DashMap::new()),
        }
    }

    pub async fn auth_done(&self, result: bool) {
        self.notifier.notify(result);
    }

    pub async fn wait_for_auth(&self) -> Option<bool> {
        self.notifier.wait().await
    }

    pub fn get_session(&self, associate_id: u16) -> UdpSession {
        // Fast path: try direct get first (cache-friendly for existing sessions)
        // This avoids the full entry API cost for the common case
        if let Some(session) = self.udp_sessions.get(&associate_id) {
            return session.clone();
        }

        // Slow path: only create new session if it doesn't exist
        self.udp_sessions
            .entry(associate_id)
            .or_insert_with(UdpSession::new)
            .clone()
    }

    pub async fn remove_session(&self, associate_id: u16) {
        let r = self.udp_sessions.remove(&associate_id);
        match r {
            Some((_associate_id, session)) => {
                // Close UDP socket before removing session
                session.close_socket().await;
                if tracing::enabled!(tracing::Level::DEBUG) {
                    debug!(
                        "Success to remove all sessions with associate_id : {}",
                        &associate_id
                    );
                }
            }
            None => {
                if tracing::enabled!(tracing::Level::DEBUG) {
                    debug!(
                        "Failed to remove session: no such associate_id : {}",
                        &associate_id
                    );
                }
            }
        }
    }
}
