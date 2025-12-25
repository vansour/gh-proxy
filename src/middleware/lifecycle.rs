//! Request lifecycle management for graceful shutdown and metrics.

use crate::errors::ProxyError;
use crate::infra;
use crate::services::shutdown::ShutdownManager;
use tokio::sync::OwnedSemaphorePermit;

/// Tracks the lifecycle of a single request for graceful shutdown.
pub struct RequestLifecycle {
    shutdown: ShutdownManager,
    completed: bool,
}

impl RequestLifecycle {
    /// Create a new lifecycle tracker and notify shutdown manager.
    pub fn new(shutdown_manager: &ShutdownManager) -> Self {
        shutdown_manager.request_started();
        Self {
            shutdown: shutdown_manager.clone(),
            completed: false,
        }
    }

    /// Mark request as successfully completed.
    pub fn success(&mut self) {
        if self.completed {
            return;
        }
        self.shutdown.request_completed();
        self.completed = true;
    }

    /// Mark request as failed.
    pub fn fail(&mut self, _error: Option<&ProxyError>) {
        if self.completed {
            return;
        }
        self.shutdown.request_completed();
        self.completed = true;
    }
}

impl Drop for RequestLifecycle {
    fn drop(&mut self) {
        if !self.completed {
            self.shutdown.request_completed();
        }
    }
}

/// Guard for managing download semaphore permits and metrics.
pub struct RequestPermitGuard {
    permit: Option<OwnedSemaphorePermit>,
    start: Option<std::time::Instant>,
}

impl RequestPermitGuard {
    /// Create a new permit guard.
    pub fn new(permit: OwnedSemaphorePermit, start: std::time::Instant) -> Self {
        Self {
            permit: Some(permit),
            start: Some(start),
        }
    }

    /// Take the permit out of the guard.
    pub fn take_permit(&mut self) -> Option<OwnedSemaphorePermit> {
        self.permit.take()
    }

    /// Take the start time out of the guard.
    pub fn take_start_time(&mut self) -> Option<std::time::Instant> {
        self.start.take()
    }
}

impl Drop for RequestPermitGuard {
    fn drop(&mut self) {
        if self.permit.take().is_some() {
            infra::metrics::HTTP_ACTIVE_REQUESTS.dec();
            if let Some(start) = self.start.take() {
                infra::metrics::HTTP_REQUEST_DURATION_SECONDS
                    .observe(start.elapsed().as_secs_f64());
            }
        }
    }
}
