//! IP-based rate limiting middleware with efficient memory management.
//!
//! Uses moka cache for automatic TTL expiration and LRU eviction,
//! preventing memory growth under high traffic.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use moka::sync::Cache;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::infra;
use crate::services::request::{detect_client_ip, trust_client_identity_headers};
use crate::state::AppState;

/// Rate limit entry tracking request count with sliding window support
struct RateLimitEntry {
    requests: Arc<std::sync::Mutex<Vec<Instant>>>,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            requests: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn cleanup_old_requests(&self, window_start: Instant) {
        let mut requests = lock_requests(&self.requests);
        requests.retain(|&t| t > window_start);
    }

    fn check_and_add(&self, now: Instant, max_requests: u32) -> bool {
        let mut requests = lock_requests(&self.requests);

        if requests.len() < max_requests as usize {
            requests.push(now);
            true
        } else {
            false
        }
    }
}

fn lock_requests(requests: &Mutex<Vec<Instant>>) -> MutexGuard<'_, Vec<Instant>> {
    requests.lock().unwrap_or_else(|poisoned| {
        tracing::warn!("Rate limiter request history lock was poisoned; recovering state");
        poisoned.into_inner()
    })
}

/// High-performance rate limiter using moka cache with sliding window algorithm
pub struct RateLimiter {
    /// Maximum requests per window
    max_requests: u32,
    /// Time window duration
    window: Duration,
    /// IP request counts with automatic TTL expiration
    requests: Cache<String, Arc<RateLimitEntry>>,
}

impl RateLimiter {
    /// Create a new rate limiter with max requests per window
    ///
    /// # Arguments
    /// * `max_requests` - Maximum requests allowed per window
    /// * `window_secs` - Window duration in seconds
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        let window = Duration::from_secs(window_secs);

        // Build cache with:
        // - Max 50,000 entries (handles large number of unique IPs)
        // - TTL equals window duration (auto-cleanup)
        // - Idle timeout for additional memory optimization
        let requests = Cache::builder()
            .max_capacity(50_000)
            .time_to_live(window)
            .time_to_idle(Duration::from_secs(window_secs * 2))
            .build();

        Self {
            max_requests,
            window,
            requests,
        }
    }

    /// Check if IP is rate limited and increment counter
    ///
    /// Returns `true` if request is allowed, `false` if rate limited
    pub fn check_and_increment(&self, ip: &str) -> bool {
        // 滑动窗口算法
        let now = Instant::now();
        let window_start = now - self.window;

        let entry = self
            .requests
            .get_with(ip.to_string(), || Arc::new(RateLimitEntry::new()));

        // 清理过期请求
        entry.cleanup_old_requests(window_start);

        // 检查是否超过限制
        entry.check_and_add(now, self.max_requests)
    }

    /// Get remaining requests for IP
    pub fn remaining(&self, ip: &str) -> u32 {
        self.requests
            .get(ip)
            .map(|entry| {
                let requests = lock_requests(&entry.requests);
                self.max_requests.saturating_sub(requests.len() as u32)
            })
            .unwrap_or(self.max_requests)
    }

    /// Get the window duration
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Get current cache size (for metrics)
    pub fn cache_size(&self) -> u64 {
        self.requests.entry_count()
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let trust_forwarded_headers =
        trust_client_identity_headers(Some(addr), state.settings.ingress.auth_header_enabled());
    let ip = detect_client_ip(&req, Some(addr), trust_forwarded_headers);
    let limiter = &state.rate_limiter;

    // Skip rate limiting for infrastructure endpoints
    let path = req.uri().path();
    if matches!(
        path,
        "/healthz" | "/readyz" | "/registry/healthz" | "/metrics" | "/"
    ) {
        return next.run(req).await;
    }

    if !limiter.check_and_increment(&ip) {
        let remaining = limiter.remaining(&ip);
        let retry_after = limiter.window().as_secs().to_string();
        infra::metrics::record_error("rate_limit");

        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("X-RateLimit-Limit", limiter.max_requests.to_string()),
                ("X-RateLimit-Remaining", remaining.to_string()),
                ("Retry-After", retry_after),
            ],
            "Rate limit exceeded. Please try again later.\n",
        )
            .into_response();
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(5, 60);

        for _ in 0..5 {
            assert!(limiter.check_and_increment("192.168.1.1"));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(3, 60);

        assert!(limiter.check_and_increment("192.168.1.1"));
        assert!(limiter.check_and_increment("192.168.1.1"));
        assert!(limiter.check_and_increment("192.168.1.1"));
        assert!(!limiter.check_and_increment("192.168.1.1")); // Should be blocked
    }

    #[test]
    fn test_rate_limiter_separate_ips() {
        let limiter = RateLimiter::new(2, 60);

        assert!(limiter.check_and_increment("192.168.1.1"));
        assert!(limiter.check_and_increment("192.168.1.1"));
        assert!(!limiter.check_and_increment("192.168.1.1"));

        // Different IP should still be allowed
        assert!(limiter.check_and_increment("192.168.1.2"));
    }

    #[test]
    fn test_remaining_requests() {
        let limiter = RateLimiter::new(10, 60);

        assert_eq!(limiter.remaining("192.168.1.1"), 10);

        limiter.check_and_increment("192.168.1.1");
        // After one request, remaining should be 9
        assert_eq!(limiter.remaining("192.168.1.1"), 9);
    }

    #[test]
    fn poisoned_rate_limit_entry_lock_recovers() {
        let entry = Arc::new(RateLimitEntry::new());
        let poisoned = Arc::clone(&entry);

        let _ = std::thread::spawn(move || {
            let _guard = poisoned.requests.lock().expect("lock for poisoning");
            panic!("poison the mutex");
        })
        .join();

        entry.cleanup_old_requests(Instant::now());
        assert!(entry.check_and_add(Instant::now(), 1));
    }
}
