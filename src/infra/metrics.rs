use axum::http::StatusCode;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Histogram, IntCounter, IntGauge, TextEncoder, register_histogram,
    register_int_counter, register_int_gauge,
};

// Prometheus metrics
pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "gh_proxy_requests_total",
        "Total proxied requests handled by the proxy"
    )
    .expect("failed to register prometheus counter: gh_proxy_requests_total")
});

// 新增：带宽统计
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

pub async fn metrics_handler() -> impl axum::response::IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&buffer).to_string();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}
