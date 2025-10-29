use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    Starting,
    Ready,
    ShuttingDown,
    Stopped,
}
pub struct ShutdownManager {
    state: Arc<RwLock<ServerState>>,
    active_requests: Arc<AtomicUsize>,
    shutdown_signal: Arc<AtomicBool>,
}
impl ShutdownManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ServerState::Starting)),
            active_requests: Arc::new(AtomicUsize::new(0)),
            shutdown_signal: Arc::new(AtomicBool::new(false)),
        }
    }
    pub async fn mark_ready(&self) {
        let mut state = self.state.write().await;
        *state = ServerState::Ready;
        info!("Server marked as ready for requests");
    }
    pub async fn is_ready(&self) -> bool {
        let state = self.state.read().await;
        *state == ServerState::Ready
    }
    pub async fn is_alive(&self) -> bool {
        let state = self.state.read().await;
        matches!(*state, ServerState::Ready | ServerState::Starting)
    }
    pub fn request_started(&self) {
        self.active_requests.fetch_add(1, Ordering::SeqCst);
        debug!(
            "Request started. Active requests: {}",
            self.get_active_requests()
        );
    }
    pub fn request_completed(&self) {
        let _ = self.active_requests.fetch_sub(1, Ordering::SeqCst);
        let active = self.get_active_requests();
        debug!("Request completed. Active requests: {}", active);
        if active == 0 && self.is_shutting_down() {
            info!("All requests completed. Ready for shutdown.");
        }
    }
    pub fn get_active_requests(&self) -> usize {
        self.active_requests.load(Ordering::SeqCst)
    }
    pub async fn get_state(&self) -> ServerState {
        *self.state.read().await
    }
    pub async fn initiate_shutdown(&self) {
        let mut state = self.state.write().await;
        if *state != ServerState::Stopped {
            *state = ServerState::ShuttingDown;
            self.shutdown_signal.store(true, Ordering::SeqCst);
            info!("Graceful shutdown initiated");
        }
    }
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_signal.load(Ordering::SeqCst)
    }
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
    pub async fn mark_stopped(&self) {
        let mut state = self.state.write().await;
        *state = ServerState::Stopped;
        info!("Server marked as stopped");
    }
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
pub struct UptimeTracker {
    start_time: std::time::Instant,
}
impl UptimeTracker {
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }
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

    #[test]
    fn test_server_state_equality() {
        assert_eq!(ServerState::Starting, ServerState::Starting);
        assert_eq!(ServerState::Ready, ServerState::Ready);
        assert_ne!(ServerState::Starting, ServerState::Ready);
    }

    #[test]
    fn test_shutdown_manager_new() {
        let manager = ShutdownManager::new();
        assert_eq!(manager.get_active_requests(), 0);
        assert!(!manager.is_shutting_down());
    }

    #[test]
    fn test_shutdown_manager_default() {
        let manager = ShutdownManager::default();
        assert_eq!(manager.get_active_requests(), 0);
        assert!(!manager.is_shutting_down());
    }

    #[test]
    fn test_shutdown_manager_clone() {
        let manager = ShutdownManager::new();
        let cloned = manager.clone();
        assert_eq!(manager.get_active_requests(), cloned.get_active_requests());
    }

    #[test]
    fn test_request_started_increments() {
        let manager = ShutdownManager::new();
        assert_eq!(manager.get_active_requests(), 0);
        manager.request_started();
        assert_eq!(manager.get_active_requests(), 1);
        manager.request_started();
        assert_eq!(manager.get_active_requests(), 2);
    }

    #[test]
    fn test_request_completed_decrements() {
        let manager = ShutdownManager::new();
        manager.request_started();
        manager.request_started();
        assert_eq!(manager.get_active_requests(), 2);
        manager.request_completed();
        assert_eq!(manager.get_active_requests(), 1);
        manager.request_completed();
        assert_eq!(manager.get_active_requests(), 0);
    }

    #[test]
    fn test_is_shutting_down() {
        let manager = ShutdownManager::new();
        assert!(!manager.is_shutting_down());
    }

    #[test]
    fn test_should_accept_request() {
        let manager = ShutdownManager::new();
        assert!(manager.should_accept_request());
    }

    #[tokio::test]
    async fn test_mark_ready() {
        let manager = ShutdownManager::new();
        manager.mark_ready().await;
        assert!(manager.is_ready().await);
    }

    #[tokio::test]
    async fn test_is_alive_when_ready() {
        let manager = ShutdownManager::new();
        manager.mark_ready().await;
        assert!(manager.is_alive().await);
    }

    #[tokio::test]
    async fn test_is_alive_when_starting() {
        let manager = ShutdownManager::new();
        assert!(manager.is_alive().await);
    }

    #[tokio::test]
    async fn test_get_state() {
        let manager = ShutdownManager::new();
        assert_eq!(manager.get_state().await, ServerState::Starting);
        manager.mark_ready().await;
        assert_eq!(manager.get_state().await, ServerState::Ready);
    }

    #[tokio::test]
    async fn test_initiate_shutdown() {
        let manager = ShutdownManager::new();
        manager.mark_ready().await;
        manager.initiate_shutdown().await;
        assert!(manager.is_shutting_down());
        assert_eq!(manager.get_state().await, ServerState::ShuttingDown);
    }

    #[tokio::test]
    async fn test_mark_stopped() {
        let manager = ShutdownManager::new();
        manager.mark_stopped().await;
        assert_eq!(manager.get_state().await, ServerState::Stopped);
    }

    #[test]
    fn test_uptime_tracker_new() {
        let tracker = UptimeTracker::new();
        let uptime = tracker.uptime_secs();
        assert_eq!(uptime, 0); // Should be 0 or close to 0 when just created
    }

    #[test]
    fn test_uptime_tracker_default() {
        let tracker = UptimeTracker::default();
        let uptime = tracker.uptime_secs();
        assert_eq!(uptime, 0); // Should be 0 or close to 0 when just created
    }

    #[test]
    fn test_uptime_tracker_increases() {
        let tracker = UptimeTracker::new();
        let uptime1 = tracker.uptime_secs();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let uptime2 = tracker.uptime_secs();
        assert!(uptime2 >= uptime1);
    }
}
