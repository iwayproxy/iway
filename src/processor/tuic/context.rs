use crate::processor::tuic::notifier::OneShotNotifier;

pub struct RuntimeContext {
    notifier: OneShotNotifier,
}

impl RuntimeContext {
    pub fn new(notifier: OneShotNotifier) -> Self {
        Self { notifier }
    }

    pub async fn auth_done(&self, result: bool) {
        self.notifier.notify(result);
    }

    pub async fn wait_for_auth(&self) {
        self.notifier.wait().await;
    }
}
