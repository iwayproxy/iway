use std::time::Duration;

use tokio::{sync::watch, time::timeout};
use tracing::debug;

pub struct OneShotNotifier {
    tx: watch::Sender<Option<bool>>,
    _rx: watch::Receiver<Option<bool>>,
}

impl OneShotNotifier {
    fn new() -> Self {
        let (tx, _rx) = watch::channel(None);
        Self { tx, _rx }
    }

    pub fn notify(&self, v: bool) {
        if self.tx.borrow().is_some() {
            return;
        }
        let _ = self.tx.send(Some(v));
    }

    pub async fn wait(&self) -> Option<bool> {
        self.wait_timeout(Duration::from_millis(100)).await
    }

    pub async fn wait_timeout(&self, dur: Duration) -> Option<bool> {
        let mut rx = self.tx.subscribe();

        if let Some(v) = *rx.borrow() {
            return Some(v);
        }

        match timeout(dur, rx.changed()).await {
            Ok(Ok(())) => *rx.borrow(),
            Ok(Err(_)) => *rx.borrow(),
            Err(_) => {
                debug!("Wait for authentication timeout after {:?}", dur);
                Some(false)
            }
        }
    }
}

impl Default for OneShotNotifier {
    fn default() -> Self {
        Self::new()
    }
}
