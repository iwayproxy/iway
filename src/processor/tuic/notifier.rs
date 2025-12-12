use std::time::Duration;

use tokio::{sync::watch, time::timeout};
use tracing::debug;

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
            debug!("Failed to send notification: {}", e);
        }
    }

    pub async fn wait(&self) -> Option<bool> {
        self.wait_timeout(Duration::from_millis(100)).await
    }

    pub async fn wait_timeout(&self, dur: Duration) -> Option<bool> {
        let mut rx = self.tx.subscribe();

        if let Some(v) = *rx.borrow() {
            return Some(v);
        }

        let fut = async {
            loop {
                if let Some(v) = *rx.borrow() {
                    return Some(v);
                }

                match rx.changed().await {
                    Ok(()) => continue,
                    Err(_) => return *rx.borrow(),
                }
            }
        };

        match timeout(dur, fut).await {
            Ok(r) => r,
            Err(_) => {
                debug!("Wait for authentication timeout after {:?}", dur);
                Some(false)
            }
        }
    }
}
