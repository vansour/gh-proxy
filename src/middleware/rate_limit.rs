//! IP-based rate limiting middleware.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limiter configuration
pub struct RateLimiter {
    /// Maximum requests per window
    max_requests: u32,
    /// Time window duration
    window: Duration,
    /// IP request counts
    requests: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
}

struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter with max requests per window
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window: Duration::from_secs(window_secs),
            requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if IP is rate limited and increment counter
    pub async fn check_and_increment(&self, ip: &str) -> bool {
        let now = Instant::now();
        let mut requests = self.requests.write().await;

        // Clean expired entries periodically (every 100 entries)
        if requests.len() > 100 {
            requests.retain(|_, entry| now.duration_since(entry.window_start) < self.window);
        }

        let entry = requests.entry(ip.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) >= self.window {
            entry.count = 0;
            entry.window_start = now;
        }

        // Check limit
        if entry.count >= self.max_requests {
            return false; // Rate limited
        }

        entry.count += 1;
        true // Allowed
    }

    /// Get remaining requests for IP
    pub async fn remaining(&self, ip: &str) -> u32 {
        let requests = self.requests.read().await;
        match requests.get(ip) {
            Some(entry) => {
                if Instant::now().duration_since(entry.window_start) >= self.window {
                    self.max_requests
                } else {
                    self.max_requests.saturating_sub(entry.count)
                }
            }
            None => self.max_requests,
        }
    }
}

/// Extract client IP from request
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

    // Skip rate limiting for health checks and metrics
    let path = req.uri().path();
    if matches!(path, "/healthz" | "/metrics" | "/") {
        return next.run(req).await;
    }

    if !limiter.check_and_increment(&ip).await {
        let remaining = limiter.remaining(&ip).await;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("X-RateLimit-Remaining", remaining.to_string()),
                ("Retry-After", "60".to_string()),
            ],
            "Rate limit exceeded. Please try again later.\n",
        )
            .into_response();
    }

    next.run(req).await
}
