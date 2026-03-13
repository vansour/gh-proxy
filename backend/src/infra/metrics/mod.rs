mod handler;
mod registry;

pub use handler::metrics_handler;
pub use registry::{
    BYTES_TRANSFERRED_TOTAL, ERRORS_TOTAL, HTTP_ACTIVE_REQUESTS, HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_TOTAL, REQUESTS_BY_METHOD, REQUESTS_BY_STATUS, REQUESTS_BY_TYPE, SERVICE_INFO,
    UPTIME_SECONDS, init_metrics, record_error, record_method, record_registry_token_cache_hit,
    record_registry_token_request, record_registry_upstream_request, record_request_type,
    record_request_type_label, record_status, snapshot_error_counts, snapshot_request_methods,
    snapshot_request_statuses, snapshot_request_types, update_uptime,
};

#[cfg(not(target_env = "msvc"))]
pub use registry::update_memory_metrics;
