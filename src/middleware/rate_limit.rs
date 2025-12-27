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
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Rate limit entry tracking request count
struct RateLimitEntry {
    count: AtomicU32,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
        }
    }

    fn increment(&self) -> u32 {
        self.count.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn get(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }
}

/// High-performance rate limiter using moka cache
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
        let entry = self
            .requests
            .get_with(ip.to_string(), || Arc::new(RateLimitEntry::new()));

        // Increment and check atomically
        let new_count = entry.increment();
        new_count <= self.max_requests
    }

    /// Get remaining requests for IP
    pub fn remaining(&self, ip: &str) -> u32 {
        self.requests
            .get(ip)
            .map(|entry| self.max_requests.saturating_sub(entry.get()))
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

/// Extract client IP from request with Cloudflare support
fn get_client_ip(req: &Request<Body>, addr: Option<SocketAddr>) -> String {
    // Check CF-Connecting-IP first (Cloudflare)
    if let Some(ip) = req
        .headers()
        .get("cf-connecting-ip")
        .and_then(|h| h.to_str().ok())
    {
        return ip.to_string();
    }

    // Check X-Forwarded-For
    if let Some(ip) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
    {
        return ip.trim().to_string();
    }

    // Check X-Real-IP
    if let Some(ip) = req.headers().get("x-real-ip").and_then(|h| h.to_str().ok()) {
        return ip.to_string();
    }

    // Fall back to socket address
    addr.map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::State(limiter): axum::extract::State<Arc<RateLimiter>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = get_client_ip(&req, Some(addr));

    // Skip rate limiting for infrastructure endpoints
    let path = req.uri().path();
    if matches!(path, "/healthz" | "/metrics" | "/") {
        return next.run(req).await;
    }

    if !limiter.check_and_increment(&ip) {
        let remaining = limiter.remaining(&ip);
        let retry_after = limiter.window().as_secs().to_string();

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
        assert_eq!(limiter.remaining("192.168.1.1"), 9);
    }
}
