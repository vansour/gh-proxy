use axum::http::StatusCode;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Histogram, IntCounter, IntGauge, TextEncoder, register_histogram,
    register_int_counter, register_int_gauge,
};
use std::sync::RwLock;
use std::time::{Duration, Instant};

// Prometheus metrics
pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "gh_proxy_requests_total",
        "Total proxied requests handled by the proxy"
    )
    .expect("failed to register prometheus counter: gh_proxy_requests_total")
});

// 带宽统计
pub static BYTES_TRANSFERRED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "gh_proxy_bytes_transferred_total",
        "Total bytes transferred to clients"
    )
    .expect("failed to register prometheus counter: gh_proxy_bytes_transferred_total")
});

pub static HTTP_ACTIVE_REQUESTS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "gh_proxy_active_requests",
        "Currently active proxied requests"
    )
    .expect("failed to register prometheus gauge: gh_proxy_active_requests")
});

pub static HTTP_REQUEST_DURATION_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "gh_proxy_request_duration_seconds",
        "Request duration in seconds",
        vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ]
    )
    .expect("failed to register prometheus histogram: gh_proxy_request_duration_seconds")
});

/// Cache for metrics output to reduce CPU overhead on high-frequency /metrics calls
/// Caches the output for 1 second before regenerating
struct MetricsCache {
    output: String,
    last_update: Instant,
}

static METRICS_CACHE: Lazy<RwLock<MetricsCache>> = Lazy::new(|| {
    RwLock::new(MetricsCache {
        output: String::new(),
        last_update: Instant::now() - Duration::from_secs(10), // Force initial update
    })
});

const METRICS_CACHE_TTL: Duration = Duration::from_secs(1);

pub async fn metrics_handler() -> impl axum::response::IntoResponse {
    // Try to use cached output first
    {
        let cache = METRICS_CACHE.read().unwrap();
        if cache.last_update.elapsed() < METRICS_CACHE_TTL && !cache.output.is_empty() {
            return (
                StatusCode::OK,
                [("content-type", "text/plain; version=0.0.4")],
                cache.output.clone(),
            );
        }
    }

    // Cache expired or empty, regenerate metrics
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::with_capacity(4096); // Pre-allocate reasonable size
    encoder
        .encode(&metric_families, &mut buffer)
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&buffer).to_string();

    // Update cache
    if let Ok(mut cache) = METRICS_CACHE.write() {
        cache.output = body.clone();
        cache.last_update = Instant::now();
    }

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}
