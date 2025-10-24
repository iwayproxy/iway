pub mod connect;
pub mod dissociate;
pub mod heartbeat;
pub mod packet;

use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio::time::{Duration, timeout};

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Processor {
    async fn process(&mut self) -> Result<()>;
}

#[derive(Clone, PartialEq, Debug)]
pub enum NotifyState {
    Success,
    Failure,
}

#[derive(Clone)]
pub struct OneShotNotifier {
    state: Arc<Mutex<Option<NotifyState>>>,
    notify: Arc<Notify>,
}

impl OneShotNotifier {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub async fn notify(&self, value: NotifyState) {
        let mut guard = self.state.lock().await;
        if guard.is_none() {
            *guard = Some(value);
            self.notify.notify_waiters();
        }
    }

    pub async fn wait(&self) -> Option<NotifyState> {
        loop {
            {
                let guard = self.state.lock().await;
                if let Some(val) = &*guard {
                    return Some(val.clone());
                }
            }
            self.notify.notified().await;
        }
    }

    pub async fn _wait_timeout(&self, dur: Duration) -> Option<NotifyState> {
        timeout(dur, self.wait()).await.ok().flatten()
    }
}
