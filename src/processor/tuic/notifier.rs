use std::time::Duration;

use tokio::{sync::watch, time::timeout};

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
        let _ = self.tx.send(Some(v));
    }

    pub async fn wait(&self) -> Option<bool> {
        self.wait_timeout(Duration::from_secs(3)).await
    }

    pub async fn wait_timeout(&self, dur: Duration) -> Option<bool> {
        let mut rx = self.tx.subscribe();

        if let Some(v) = *rx.borrow() {
            return Some(v);
        }

        timeout(dur, async {
            loop {
                if rx.changed().await.is_err() {
                    return *rx.borrow(); // sender dropped
                }
                if let Some(v) = *rx.borrow() {
                    return Some(v);
                }
            }
        })
        .await
        .unwrap_or(None)
    }
}
