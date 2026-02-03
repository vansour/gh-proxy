//! IP-based rate limiting middleware with efficient memory management.
//!
//! Uses moka cache for automatic TTL expiration and LRU eviction,
//! preventing memory growth under high traffic.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use moka::sync::Cache;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        let mut requests = self.requests.lock().unwrap();
        requests.retain(|&t| t > window_start);
    }

    fn check_and_add(&self, now: Instant, max_requests: u32) -> bool {
        let mut requests = self.requests.lock().unwrap();

        if requests.len() < max_requests as usize {
            requests.push(now);
            true
        } else {
            false
        }
    }
}

/// High-performance rate limiter using moka cache with sliding window algorithm
pub struct RateLimiter {
    /// Maximum requests per window
    max_requests: u32,
    /// Time window duration
    window: Duration,
    /// IP request counts with automatic TTL expiration
    requests: Cache<String, Arc<RateLimitEntry>>,
    /// CDN-specific configuration
    ip_whitelist: Vec<String>,
    /// Enable IP whitelist for CDN edge nodes
    enable_ip_whitelist: bool,
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
            ip_whitelist: Vec::new(),
            enable_ip_whitelist: false,
        }
    }

    /// Create a new rate limiter with CDN-specific configuration
    pub fn new_with_config(max_requests: u32, window_secs: u64, ip_whitelist: Vec<String>) -> Self {
        let window = Duration::from_secs(window_secs);

        let requests = Cache::builder()
            .max_capacity(50_000)
            .time_to_live(window)
            .time_to_idle(Duration::from_secs(window_secs * 2))
            .build();

        Self {
            max_requests,
            window,
            requests,
            ip_whitelist,
            enable_ip_whitelist: true,
        }
    }

    /// Check if IP is rate limited and increment counter
    ///
    /// Returns `true` if request is allowed, `false` if rate limited
    pub fn check_and_increment(&self, ip: &str, headers: &HeaderMap) -> bool {
        if self.enable_ip_whitelist && self.is_trusted_ip(ip, headers) {
            return true;
        }

        // 如果启用了 IP 白名单但 IP 不在白名单中，拒绝访问
        if self.enable_ip_whitelist && !self.ip_whitelist.contains(&ip.to_string()) {
            return false;
        }

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

    fn is_trusted_ip(&self, ip: &str, headers: &HeaderMap) -> bool {
        if headers.contains_key("cf-connecting-ip") {
            return true;
        }

        // 检查 IP 白名单
        // 简单的 IP 匹配（不支持 CIDR 格式）
        self.ip_whitelist.contains(&ip.to_string())
    }

    /// Get remaining requests for IP
    pub fn remaining(&self, ip: &str) -> u32 {
        self.requests
            .get(ip)
            .map(|entry| {
                let requests = entry.requests.lock().unwrap();
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

fn get_client_ip(req: &Request<Body>, addr: Option<SocketAddr>) -> String {
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

    if !limiter.check_and_increment(&ip, req.headers()) {
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
        let headers = HeaderMap::new();

        for _ in 0..5 {
            assert!(limiter.check_and_increment("192.168.1.1", &headers));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(3, 60);
        let headers = HeaderMap::new();

        assert!(limiter.check_and_increment("192.168.1.1", &headers));
        assert!(limiter.check_and_increment("192.168.1.1", &headers));
        assert!(limiter.check_and_increment("192.168.1.1", &headers));
        assert!(!limiter.check_and_increment("192.168.1.1", &headers)); // Should be blocked
    }

    #[test]
    fn test_rate_limiter_separate_ips() {
        let limiter = RateLimiter::new(2, 60);
        let headers = HeaderMap::new();

        assert!(limiter.check_and_increment("192.168.1.1", &headers));
        assert!(limiter.check_and_increment("192.168.1.1", &headers));
        assert!(!limiter.check_and_increment("192.168.1.1", &headers));

        // Different IP should still be allowed
        assert!(limiter.check_and_increment("192.168.1.2", &headers));
    }

    #[test]
    fn test_remaining_requests() {
        let limiter = RateLimiter::new(10, 60);
        let headers = HeaderMap::new();

        assert_eq!(limiter.remaining("192.168.1.1"), 10);

        limiter.check_and_increment("192.168.1.1", &headers);
        // After one request, remaining should be 9
        assert_eq!(limiter.remaining("192.168.1.1"), 9);
    }

    #[test]
    fn test_ip_whitelist() {
        let limiter = RateLimiter::new_with_config(3, 60, vec!["10.0.0.1".to_string()]);
        let headers = HeaderMap::new();

        // Whitelisted IP should bypass rate limiting
        for _ in 0..10 {
            assert!(limiter.check_and_increment("10.0.0.1", &headers));
        }
    }
}
