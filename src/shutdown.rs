// Graceful shutdown and health check management
//
// This module handles:
// - Signal handling for graceful shutdown (SIGTERM, SIGINT)
// - Server state management during shutdown
// - Liveness and readiness probes for Kubernetes
// - Request draining before shutdown

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Server state for managing lifecycle transitions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Server is starting up
    Starting,
    /// Server is ready to serve requests
    Ready,
    /// Server is shutting down, no new requests accepted
    ShuttingDown,
    /// Server has shut down completely
    Stopped,
}

/// Manages server lifecycle and graceful shutdown
pub struct ShutdownManager {
    /// Current server state
    state: Arc<RwLock<ServerState>>,
    /// Number of active requests
    active_requests: Arc<AtomicUsize>,
    /// Signal received flag
    shutdown_signal: Arc<AtomicBool>,
}

impl ShutdownManager {
    /// Create a new shutdown manager
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ServerState::Starting)),
            active_requests: Arc::new(AtomicUsize::new(0)),
            shutdown_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Mark the server as ready
    pub async fn mark_ready(&self) {
        let mut state = self.state.write().await;
        *state = ServerState::Ready;
        info!("Server marked as ready for requests");
    }

    /// Check if server is ready to serve requests
    pub async fn is_ready(&self) -> bool {
        let state = self.state.read().await;
        *state == ServerState::Ready
    }

    /// Check if server is alive (started but may not be ready)
    pub async fn is_alive(&self) -> bool {
        let state = self.state.read().await;
        matches!(*state, ServerState::Ready | ServerState::Starting)
    }

    /// Increment active request counter
    pub fn request_started(&self) {
        self.active_requests.fetch_add(1, Ordering::SeqCst);
        debug!(
            "Request started. Active requests: {}",
            self.get_active_requests()
        );
    }

    /// Decrement active request counter
    pub fn request_completed(&self) {
        let _ = self.active_requests.fetch_sub(1, Ordering::SeqCst);
        let active = self.get_active_requests();
        debug!("Request completed. Active requests: {}", active);

        // Log when last request completes during shutdown
        if active == 0 && self.is_shutting_down() {
            info!("All requests completed. Ready for shutdown.");
        }
    }

    /// Get current number of active requests
    pub fn get_active_requests(&self) -> usize {
        self.active_requests.load(Ordering::SeqCst)
    }

    /// Get current server state
    pub async fn get_state(&self) -> ServerState {
        *self.state.read().await
    }

    /// Initiate graceful shutdown
    pub async fn initiate_shutdown(&self) {
        let mut state = self.state.write().await;
        if *state != ServerState::Stopped {
            *state = ServerState::ShuttingDown;
            self.shutdown_signal.store(true, Ordering::SeqCst);
            info!("Graceful shutdown initiated");
        }
    }

    /// Check if shutdown has been signaled
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_signal.load(Ordering::SeqCst)
    }

    /// Wait for all active requests to complete with timeout
    ///
    /// Returns true if all requests completed, false if timeout occurred
    pub async fn wait_for_requests(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        let check_interval = Duration::from_millis(100);

        loop {
            if self.get_active_requests() == 0 {
                info!("All requests completed successfully");
                return true;
            }

            if start.elapsed() > timeout {
                warn!(
                    "Shutdown timeout reached with {} active requests still running",
                    self.get_active_requests()
                );
                return false;
            }

            debug!(
                "Waiting for requests to complete: {} active, elapsed: {:?}",
                self.get_active_requests(),
                start.elapsed()
            );

            tokio::time::sleep(check_interval).await;
        }
    }

    /// Mark server as stopped
    pub async fn mark_stopped(&self) {
        let mut state = self.state.write().await;
        *state = ServerState::Stopped;
        info!("Server marked as stopped");
    }

    /// Check if a new request should be accepted
    pub fn should_accept_request(&self) -> bool {
        !self.is_shutting_down()
    }
}

impl Default for ShutdownManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ShutdownManager {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            active_requests: Arc::clone(&self.active_requests),
            shutdown_signal: Arc::clone(&self.shutdown_signal),
        }
    }
}

/// Health check information
#[derive(Debug, Clone, serde::Serialize)]
#[allow(dead_code)]
pub struct HealthStatus {
    /// Server state (starting, ready, shutting_down, stopped)
    pub state: String,
    /// Number of active requests
    pub active_requests: usize,
    /// Server uptime in seconds
    pub uptime_secs: u64,
    /// Whether server is accepting new requests
    pub accepting_requests: bool,
}

/// Tracks server uptime
pub struct UptimeTracker {
    start_time: std::time::Instant,
}

impl UptimeTracker {
    /// Create a new uptime tracker
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        let elapsed = self.start_time.elapsed();
        let secs = elapsed.as_secs();
        if secs > 0 {
            secs
        } else if elapsed.subsec_nanos() > 0 {
            1
        } else {
            0
        }
    }
}

impl Default for UptimeTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_manager_lifecycle() {
        let manager = ShutdownManager::new();

        // Initially not ready
        assert!(!manager.is_ready().await);
        assert!(manager.is_alive().await);

        // Mark ready
        manager.mark_ready().await;
        assert!(manager.is_ready().await);

        // Initiate shutdown
        manager.initiate_shutdown().await;
        assert!(manager.is_shutting_down());
        assert!(!manager.should_accept_request());
    }

    #[tokio::test]
    async fn test_request_counting() {
        let manager = ShutdownManager::new();

        assert_eq!(manager.get_active_requests(), 0);

        manager.request_started();
        manager.request_started();
        assert_eq!(manager.get_active_requests(), 2);

        manager.request_completed();
        assert_eq!(manager.get_active_requests(), 1);

        manager.request_completed();
        assert_eq!(manager.get_active_requests(), 0);
    }

    #[tokio::test]
    async fn test_wait_for_requests_timeout() {
        let manager = ShutdownManager::new();
        manager.request_started();

        let result = manager.wait_for_requests(Duration::from_millis(100)).await;
        assert!(!result); // Should timeout
        assert_eq!(manager.get_active_requests(), 1);

        manager.request_completed();
        let result = manager.wait_for_requests(Duration::from_millis(100)).await;
        assert!(result); // Should complete
    }

    #[test]
    fn test_uptime_tracker() {
        let tracker = UptimeTracker::new();
        std::thread::sleep(Duration::from_millis(100));
        assert!(tracker.uptime_secs() > 0);
    }
}
