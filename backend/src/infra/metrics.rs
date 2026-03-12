//! Prometheus metrics for monitoring.

use crate::utils::constants::cache;
use crate::{services::request::ops_endpoint_access_allowed, state::AppState};
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Histogram, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, TextEncoder,
    register_histogram, register_int_counter, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

// ============================================================================
// Basic metrics
// ============================================================================

/// Total proxied requests handled
pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "gh_proxy_requests_total",
        "Total HTTP requests handled by gh-proxy"
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
        cache::REQUEST_DURATION_BUCKETS.to_vec()
    )
    .expect("failed to register prometheus histogram: gh_proxy_request_duration_seconds")
});

// ============================================================================
// Enhanced metrics
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
// Connection pool metrics
// ============================================================================

// Connection pool metrics are tracked by hyper internally
// These can be extended if needed

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
    record_request_type_label(classify_request_type(path));
}

pub fn record_request_type_label(request_type: &str) {
    REQUESTS_BY_TYPE.with_label_values(&[request_type]).inc();
}

fn classify_request_type(path: &str) -> &'static str {
    if path.starts_with("/github/") {
        "github"
    } else if path.starts_with("/v2/") {
        "registry"
    } else if path.starts_with("/api/") {
        "api"
    } else if path.starts_with("/assets/") || matches!(path, "/" | "/status" | "/favicon.ico") {
        "static"
    } else if matches!(
        path,
        "/metrics" | "/healthz" | "/readyz" | "/registry/healthz"
    ) || path.starts_with("/debug/")
    {
        "infra"
    } else {
        "fallback"
    }
}

/// Record request by HTTP method
pub fn record_method(method: &str) {
    REQUESTS_BY_METHOD.with_label_values(&[method]).inc();
}

/// Record error by type
pub fn record_error(error_type: &str) {
    ERRORS_TOTAL.with_label_values(&[error_type]).inc();
}

fn snapshot_counter_vec(counter: &IntCounterVec, labels: &[&str]) -> BTreeMap<String, u64> {
    labels
        .iter()
        .map(|label| {
            (
                (*label).to_string(),
                counter.with_label_values(&[*label]).get(),
            )
        })
        .collect()
}

pub fn snapshot_request_statuses() -> BTreeMap<String, u64> {
    snapshot_counter_vec(&REQUESTS_BY_STATUS, &["2xx", "3xx", "4xx", "5xx", "other"])
}

pub fn snapshot_request_types() -> BTreeMap<String, u64> {
    snapshot_counter_vec(
        &REQUESTS_BY_TYPE,
        &["github", "registry", "api", "static", "infra", "fallback"],
    )
}

pub fn snapshot_request_methods() -> BTreeMap<String, u64> {
    snapshot_counter_vec(
        &REQUESTS_BY_METHOD,
        &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
}

pub fn snapshot_error_counts() -> BTreeMap<String, u64> {
    snapshot_counter_vec(
        &ERRORS_TOTAL,
        &[
            "upstream",
            "rate_limit",
            "size_exceeded",
            "host_not_allowed",
            "origin_auth_failed",
            "method_not_allowed",
            "invalid_target",
            "timeout",
            "other",
        ],
    )
}

/// Update uptime gauge
pub fn update_uptime(uptime_secs: u64) {
    UPTIME_SECONDS.set(uptime_secs as i64);
}

/// Update memory metrics (Linux only)
#[cfg(not(target_env = "msvc"))]
pub fn update_memory_metrics() {
    // Memory metrics can be tracked via jemalloc stats if needed
    // This is optional and may be extended in the future
}

// ============================================================================
// Metrics cache and handler
// ============================================================================

/// Cache TTL for metrics output
const METRICS_CACHE_TTL: Duration = cache::METRICS_CACHE_TTL;

/// Cache for metrics output to reduce CPU overhead
struct MetricsCache {
    output: String,
    last_update: Instant,
}

static METRICS_CACHE: Lazy<RwLock<MetricsCache>> = Lazy::new(|| {
    RwLock::new(MetricsCache {
        output: String::new(),
        last_update: Instant::now(),
    })
});

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| {
        tracing::warn!("Metrics cache read lock was poisoned; recovering state");
        poisoned.into_inner()
    })
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|poisoned| {
        tracing::warn!("Metrics cache write lock was poisoned; recovering state");
        poisoned.into_inner()
    })
}

/// Metrics handler for Prometheus scraping
pub async fn metrics_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> axum::response::Response {
    if !ops_endpoint_access_allowed(addr, state.settings.debug.metrics_enabled) {
        return (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain; charset=utf-8")],
            "Metrics endpoint is disabled.\n",
        )
            .into_response();
    }

    // Ensure service info is initialized and update uptime
    let _ = &*SERVICE_INFO;
    update_uptime(state.uptime_tracker.uptime_secs());

    // Update memory metrics
    #[cfg(not(target_env = "msvc"))]
    update_memory_metrics();

    // Try to use cached output first
    {
        let cache = read_lock(&METRICS_CACHE);
        if cache.last_update.elapsed() < METRICS_CACHE_TTL && !cache.output.is_empty() {
            return (
                StatusCode::OK,
                [("content-type", "text/plain; version=0.0.4")],
                cache.output.clone(),
            )
                .into_response();
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
    let mut cache = write_lock(&METRICS_CACHE);
    cache.output = body.clone();
    cache.last_update = Instant::now();

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{classify_request_type, read_lock, write_lock};
    use std::sync::{Arc, RwLock};

    #[test]
    fn poisoned_metrics_read_lock_recovers() {
        let lock = Arc::new(RwLock::new(5u64));
        let poisoned = Arc::clone(&lock);

        let _ = std::thread::spawn(move || {
            let _guard = poisoned.write().expect("lock for poisoning");
            panic!("poison the rwlock");
        })
        .join();

        assert_eq!(*read_lock(&lock), 5);
    }

    #[test]
    fn poisoned_metrics_write_lock_recovers() {
        let lock = Arc::new(RwLock::new(5u64));
        let poisoned = Arc::clone(&lock);

        let _ = std::thread::spawn(move || {
            let _guard = poisoned.write().expect("lock for poisoning");
            panic!("poison the rwlock");
        })
        .join();

        *write_lock(&lock) = 8;
        assert_eq!(*read_lock(&lock), 8);
    }

    #[test]
    fn classify_request_type_maps_known_routes() {
        assert_eq!(
            classify_request_type("/github/owner/repo/file.txt"),
            "github"
        );
        assert_eq!(
            classify_request_type("/v2/library/test/blobs/sha256:abc"),
            "registry"
        );
        assert_eq!(classify_request_type("/api/stats"), "api");
        assert_eq!(classify_request_type("/status"), "static");
        assert_eq!(classify_request_type("/metrics"), "infra");
        assert_eq!(
            classify_request_type("/https://github.com/owner/repo/blob/main/file.txt"),
            "fallback"
        );
    }
}
