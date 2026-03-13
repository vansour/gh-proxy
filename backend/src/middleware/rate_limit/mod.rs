//! IP-based rate limiting middleware with efficient memory management.

mod entry;

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
use std::time::{Duration, Instant};

use crate::infra;
use crate::services::request::{detect_client_ip, trust_client_identity_headers};
use crate::state::AppState;

use self::entry::RateLimitEntry;

pub struct RateLimiter {
    max_requests: u32,
    window: Duration,
    requests: Cache<String, Arc<RateLimitEntry>>,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
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
        }
    }

    pub fn check_and_increment(&self, ip: &str) -> bool {
        let now = Instant::now();
        let window_start = now - self.window;

        let entry = self
            .requests
            .get_with(ip.to_string(), || Arc::new(RateLimitEntry::new()));
        entry.cleanup_old_requests(window_start);
        entry.check_and_add(now, self.max_requests)
    }

    pub fn remaining(&self, ip: &str) -> u32 {
        self.requests
            .get(ip)
            .map(|entry| {
                self.max_requests
                    .saturating_sub(entry.request_count() as u32)
            })
            .unwrap_or(self.max_requests)
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    pub fn cache_size(&self) -> u64 {
        self.requests.entry_count()
    }
}

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
mod tests;
