use std::time::Duration;

use tokio::{sync::watch, time::timeout};
use tracing::{debug, error};

pub struct OneShotNotifier {
    tx: watch::Sender<Option<bool>>,
    _rx: watch::Receiver<Option<bool>>,
}

impl OneShotNotifier {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(None);

        Self { tx, _rx }
    }

    pub fn notify(&self, v: bool) {
        if self.tx.borrow().is_some() {
            return;
        }

        if let Err(e) = self.tx.send(Some(v)) {
            error!("Failed to send notity, error: {}", e);
        }
    }

    pub async fn wait(&self) -> Option<bool> {
        // default timeout: 3 seconds
        self.wait_timeout(Duration::from_secs(3)).await
    }

    pub async fn wait_timeout(&self, dur: Duration) -> Option<bool> {
        let mut rx = self.tx.subscribe();

        // fast path: value already set
        if let Some(v) = *rx.borrow() {
            return Some(v);
        }

        // Run the waiting loop inside a single timeout so `dur` is the total
        // maximum time we wait. The async block returns Some(v) if a value
        // appears, or the final borrowed value (possibly None) if the sender
        // is dropped.
        let fut = async {
            loop {
                // fast path: value already set
                if let Some(v) = *rx.borrow() {
                    return Some(v);
                }

                match rx.changed().await {
                    Ok(()) => continue,
                    Err(_) => return *rx.borrow(), // sender dropped
                }
            }
        };

        match timeout(dur, fut).await {
            Ok(r) => r,
            Err(e) => {
                debug!("This should not happen, there must be something wrong! error: {e}");
                None
            }
        }
    }
}
