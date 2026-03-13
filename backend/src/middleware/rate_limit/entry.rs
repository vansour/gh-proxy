use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

pub(super) struct RateLimitEntry {
    pub(super) requests: Arc<Mutex<Vec<Instant>>>,
}

impl RateLimitEntry {
    pub(super) fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(super) fn cleanup_old_requests(&self, window_start: Instant) {
        let mut requests = lock_requests(&self.requests);
        requests.retain(|&t| t > window_start);
    }

    pub(super) fn check_and_add(&self, now: Instant, max_requests: u32) -> bool {
        let mut requests = lock_requests(&self.requests);

        if requests.len() < max_requests as usize {
            requests.push(now);
            true
        } else {
            false
        }
    }

    pub(super) fn request_count(&self) -> usize {
        lock_requests(&self.requests).len()
    }
}

pub(super) fn lock_requests(requests: &Mutex<Vec<Instant>>) -> MutexGuard<'_, Vec<Instant>> {
    requests.lock().unwrap_or_else(|poisoned| {
        tracing::warn!("Rate limiter request history lock was poisoned; recovering state");
        poisoned.into_inner()
    })
}
