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

    pub async fn wait_for_auth(&self) {
        self.notifier.wait().await;
    }

    pub fn get_session(&self, associate_id: u16) -> UdpSession {
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
                debug!(
                    "Success to remove all sessions with associate_id : {}",
                    &associate_id
                );
            }
            None => {
                debug!(
                    "Failed to remove session: no such associate_id : {}",
                    &associate_id
                );
            }
        }
    }
}
