use super::metrics::{
    ERRORS_TOTAL, REGISTRY_TOKEN_CACHE_HITS_TOTAL, REGISTRY_TOKEN_REQUEST_DURATION_SECONDS,
    REGISTRY_TOKEN_REQUESTS_TOTAL, REGISTRY_UPSTREAM_REQUEST_DURATION_SECONDS,
    REGISTRY_UPSTREAM_REQUESTS_TOTAL, REQUESTS_BY_METHOD, REQUESTS_BY_STATUS, REQUESTS_BY_TYPE,
    UPTIME_SECONDS,
};

fn status_category(status_code: u16) -> &'static str {
    match status_code {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

pub fn record_status(status_code: u16) {
    REQUESTS_BY_STATUS
        .with_label_values(&[status_category(status_code)])
        .inc();
}

pub fn record_request_type(path: &str) {
    record_request_type_label(classify_request_type(path));
}

pub fn record_request_type_label(request_type: &str) {
    REQUESTS_BY_TYPE.with_label_values(&[request_type]).inc();
}

pub(super) fn classify_request_type(path: &str) -> &'static str {
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

pub fn record_method(method: &str) {
    REQUESTS_BY_METHOD.with_label_values(&[method]).inc();
}

pub fn record_error(error_type: &str) {
    ERRORS_TOTAL.with_label_values(&[error_type]).inc();
}

pub fn update_uptime(uptime_secs: u64) {
    UPTIME_SECONDS.set(uptime_secs as i64);
}

pub fn record_registry_upstream_request(
    operation: &str,
    registry_host: &str,
    status_code: Option<u16>,
    duration_secs: f64,
) {
    let result = status_code.map(status_category).unwrap_or("error");
    REGISTRY_UPSTREAM_REQUESTS_TOTAL
        .with_label_values(&[operation, registry_host, result])
        .inc();
    REGISTRY_UPSTREAM_REQUEST_DURATION_SECONDS
        .with_label_values(&[operation, registry_host])
        .observe(duration_secs);
}

pub fn record_registry_token_cache_hit(registry_host: &str) {
    REGISTRY_TOKEN_CACHE_HITS_TOTAL
        .with_label_values(&[registry_host])
        .inc();
}

pub fn record_registry_token_request(registry_host: &str, result: &str, duration_secs: f64) {
    REGISTRY_TOKEN_REQUESTS_TOTAL
        .with_label_values(&[registry_host, result])
        .inc();
    REGISTRY_TOKEN_REQUEST_DURATION_SECONDS
        .with_label_values(&[registry_host])
        .observe(duration_secs);
}

pub fn init_metrics() {
    let _ = &*super::metrics::HTTP_REQUESTS_TOTAL;
    let _ = &*super::metrics::BYTES_TRANSFERRED_TOTAL;
    let _ = &*super::metrics::HTTP_ACTIVE_REQUESTS;
    let _ = &*super::metrics::HTTP_REQUEST_DURATION_SECONDS;
    let _ = &*super::metrics::ERRORS_TOTAL;
    let _ = &*super::metrics::REQUESTS_BY_METHOD;
    let _ = &*super::metrics::REQUESTS_BY_STATUS;
    let _ = &*super::metrics::REQUESTS_BY_TYPE;
    let _ = &*super::metrics::SERVICE_INFO;
    let _ = &*super::metrics::UPTIME_SECONDS;
    let _ = &*super::metrics::REGISTRY_UPSTREAM_REQUESTS_TOTAL;
    let _ = &*super::metrics::REGISTRY_UPSTREAM_REQUEST_DURATION_SECONDS;
    let _ = &*super::metrics::REGISTRY_TOKEN_CACHE_HITS_TOTAL;
    let _ = &*super::metrics::REGISTRY_TOKEN_REQUESTS_TOTAL;
    let _ = &*super::metrics::REGISTRY_TOKEN_REQUEST_DURATION_SECONDS;

    for label in ["2xx", "3xx", "4xx", "5xx", "other"] {
        let _ = REQUESTS_BY_STATUS.with_label_values(&[label]).get();
    }
    for label in ["github", "registry", "api", "static", "infra", "fallback"] {
        let _ = REQUESTS_BY_TYPE.with_label_values(&[label]).get();
    }
    for label in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        let _ = REQUESTS_BY_METHOD.with_label_values(&[label]).get();
    }
    for label in [
        "upstream",
        "rate_limit",
        "size_exceeded",
        "host_not_allowed",
        "origin_auth_failed",
        "method_not_allowed",
        "invalid_target",
        "timeout",
        "other",
    ] {
        let _ = ERRORS_TOTAL.with_label_values(&[label]).get();
    }
}

#[cfg(not(target_env = "msvc"))]
pub fn update_memory_metrics() {}
