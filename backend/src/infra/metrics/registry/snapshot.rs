use super::metrics::{ERRORS_TOTAL, REQUESTS_BY_METHOD, REQUESTS_BY_STATUS, REQUESTS_BY_TYPE};
use prometheus::IntCounterVec;
use std::collections::BTreeMap;

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
