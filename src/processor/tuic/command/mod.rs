pub mod authenticate;
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
        // 使用默认的10秒超时
        self.wait_timeout(Duration::from_secs(3)).await
    }

    /// Wait for a notification but return None on timeout.
    ///
    /// Returns `Some(NotifyState)` if a notification was received before the timeout,
    /// or `None` if the timeout elapsed.
    pub async fn wait_timeout(&self, dur: Duration) -> Option<NotifyState> {
        match timeout(dur, async {
            loop {
                let guard = self.state.lock().await;
                if let Some(val) = &*guard {
                    return Some(val.clone());
                }
                drop(guard);
                self.notify.notified().await;
            }
        })
        .await
        {
            Ok(result) => result,
            Err(_) => None,
        }
    }
}
