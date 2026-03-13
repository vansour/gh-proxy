use crate::utils::constants::cache;
use once_cell::sync::Lazy;
use prometheus::{
    Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, register_histogram,
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec,
};

pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "gh_proxy_requests_total",
        "Total HTTP requests handled by gh-proxy"
    )
    .expect("failed to register prometheus counter: gh_proxy_requests_total")
});

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
        cache::REQUEST_DURATION_BUCKETS.to_vec()
    )
    .expect("failed to register prometheus histogram: gh_proxy_request_duration_seconds")
});

pub static REQUESTS_BY_STATUS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_requests_by_status",
        "Requests by HTTP status code category",
        &["status"]
    )
    .expect("failed to register prometheus counter: gh_proxy_requests_by_status")
});

pub static REQUESTS_BY_TYPE: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_requests_by_type",
        "Requests by path type",
        &["type"]
    )
    .expect("failed to register prometheus counter: gh_proxy_requests_by_type")
});

pub static REQUESTS_BY_METHOD: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_requests_by_method",
        "Requests by HTTP method",
        &["method"]
    )
    .expect("failed to register prometheus counter: gh_proxy_requests_by_method")
});

pub static ERRORS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("gh_proxy_errors_total", "Errors by type", &["error_type"])
        .expect("failed to register prometheus counter: gh_proxy_errors_total")
});

pub static SERVICE_INFO: Lazy<IntGaugeVec> = Lazy::new(|| {
    let gauge = register_int_gauge_vec!("gh_proxy_info", "Service information", &["version"])
        .expect("failed to register prometheus gauge: gh_proxy_info");
    gauge.with_label_values(&[env!("CARGO_PKG_VERSION")]).set(1);
    gauge
});

pub static UPTIME_SECONDS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("gh_proxy_uptime_seconds", "Service uptime in seconds")
        .expect("failed to register prometheus gauge: gh_proxy_uptime_seconds")
});

pub static REGISTRY_UPSTREAM_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_registry_upstream_requests_total",
        "Registry upstream requests by operation, host, and result",
        &["operation", "registry_host", "result"]
    )
    .expect("failed to register prometheus counter: gh_proxy_registry_upstream_requests_total")
});

pub static REGISTRY_UPSTREAM_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "gh_proxy_registry_upstream_request_duration_seconds",
        "Registry upstream request duration in seconds",
        &["operation", "registry_host"],
        cache::REQUEST_DURATION_BUCKETS.to_vec()
    )
    .expect(
        "failed to register prometheus histogram: gh_proxy_registry_upstream_request_duration_seconds",
    )
});

pub static REGISTRY_TOKEN_CACHE_HITS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_registry_token_cache_hits_total",
        "Registry bearer token cache hits by registry host",
        &["registry_host"]
    )
    .expect("failed to register prometheus counter: gh_proxy_registry_token_cache_hits_total")
});

pub static REGISTRY_TOKEN_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_registry_token_requests_total",
        "Registry bearer token requests by registry host and result",
        &["registry_host", "result"]
    )
    .expect("failed to register prometheus counter: gh_proxy_registry_token_requests_total")
});

pub static REGISTRY_TOKEN_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "gh_proxy_registry_token_request_duration_seconds",
        "Registry bearer token request duration in seconds",
        &["registry_host"],
        cache::REQUEST_DURATION_BUCKETS.to_vec()
    )
    .expect(
        "failed to register prometheus histogram: gh_proxy_registry_token_request_duration_seconds",
    )
});
