//! Prometheus metrics for monitoring.

use axum::http::StatusCode;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Histogram, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, TextEncoder,
    register_histogram, register_int_counter, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec,
};
use std::sync::RwLock;
use std::time::{Duration, Instant};

// ============================================================================
// Basic metrics (existing)
// ============================================================================

/// Total proxied requests handled
pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "gh_proxy_requests_total",
        "Total proxied requests handled by the proxy"
    )
    .expect("failed to register prometheus counter: gh_proxy_requests_total")
});

/// Total bytes transferred to clients
pub static BYTES_TRANSFERRED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "gh_proxy_bytes_transferred_total",
        "Total bytes transferred to clients"
    )
    .expect("failed to register prometheus counter: gh_proxy_bytes_transferred_total")
});

/// Currently active proxied requests
pub static HTTP_ACTIVE_REQUESTS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "gh_proxy_active_requests",
        "Currently active proxied requests"
    )
    .expect("failed to register prometheus gauge: gh_proxy_active_requests")
});

/// Request duration histogram
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

// ============================================================================
// Enhanced metrics (new)
// ============================================================================

/// Requests by HTTP status code category (2xx, 3xx, 4xx, 5xx)
pub static REQUESTS_BY_STATUS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_requests_by_status",
        "Requests by HTTP status code category",
        &["status"]
    )
    .expect("failed to register prometheus counter: gh_proxy_requests_by_status")
});

/// Requests by path type (github, registry, static, api, fallback)
pub static REQUESTS_BY_TYPE: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_requests_by_type",
        "Requests by path type",
        &["type"]
    )
    .expect("failed to register prometheus counter: gh_proxy_requests_by_type")
});

/// Requests by HTTP method
pub static REQUESTS_BY_METHOD: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_requests_by_method",
        "Requests by HTTP method",
        &["method"]
    )
    .expect("failed to register prometheus counter: gh_proxy_requests_by_method")
});

/// Error counts by error type
pub static ERRORS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("gh_proxy_errors_total", "Errors by type", &["error_type"])
        .expect("failed to register prometheus counter: gh_proxy_errors_total")
});

/// Service info gauge (always 1, used for version label)
pub static SERVICE_INFO: Lazy<IntGaugeVec> = Lazy::new(|| {
    let gauge = register_int_gauge_vec!("gh_proxy_info", "Service information", &["version"])
        .expect("failed to register prometheus gauge: gh_proxy_info");
    // Set version to 1
    gauge.with_label_values(&[env!("CARGO_PKG_VERSION")]).set(1);
    gauge
});

/// Service uptime in seconds
pub static UPTIME_SECONDS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("gh_proxy_uptime_seconds", "Service uptime in seconds")
        .expect("failed to register prometheus gauge: gh_proxy_uptime_seconds")
});

// ============================================================================
// Helper functions
// ============================================================================

/// Record request by status code category
pub fn record_status(status_code: u16) {
    let category = match status_code {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };
    REQUESTS_BY_STATUS.with_label_values(&[category]).inc();
}

/// Record request by path type
pub fn record_request_type(path: &str) {
    let request_type = if path.starts_with("/github/") {
        "github"
    } else if path.starts_with("/v2/") {
        "registry"
    } else if path.starts_with("/api/") {
        "api"
    } else if matches!(
        path,
        "/" | "/style.css" | "/script.js" | "/favicon.ico" | "/docker"
    ) {
        "static"
    } else if path == "/metrics" || path == "/healthz" {
        "infra"
    } else {
        "fallback"
    };
    REQUESTS_BY_TYPE.with_label_values(&[request_type]).inc();
}

/// Record request by HTTP method
pub fn record_method(method: &str) {
    REQUESTS_BY_METHOD.with_label_values(&[method]).inc();
}

/// Record error by type
pub fn record_error(error_type: &str) {
    ERRORS_TOTAL.with_label_values(&[error_type]).inc();
}

/// Update uptime gauge
pub fn update_uptime(uptime_secs: u64) {
    UPTIME_SECONDS.set(uptime_secs as i64);
}

// ============================================================================
// Metrics cache and handler
// ============================================================================

/// Cache for metrics output to reduce CPU overhead
struct MetricsCache {
    output: String,
    last_update: Instant,
}

static METRICS_CACHE: Lazy<RwLock<MetricsCache>> = Lazy::new(|| {
    RwLock::new(MetricsCache {
        output: String::new(),
        last_update: Instant::now() - Duration::from_secs(10),
    })
});

const METRICS_CACHE_TTL: Duration = Duration::from_secs(1);

pub async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
) -> impl axum::response::IntoResponse {
    // Ensure service info is initialized and update uptime
    let _ = &*SERVICE_INFO;
    update_uptime(state.uptime_tracker.uptime_secs());

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
    let mut buffer = Vec::with_capacity(8192);
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
