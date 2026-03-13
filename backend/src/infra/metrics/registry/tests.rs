use super::classify::{classify_request_type, init_metrics};

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

#[test]
fn init_metrics_registers_documented_metric_families() {
    init_metrics();
    crate::cache::metrics::init_metrics();

    let families = prometheus::gather();
    let names: std::collections::BTreeSet<_> = families
        .into_iter()
        .map(|family| family.name().to_string())
        .collect();

    for metric in [
        "gh_proxy_requests_total",
        "gh_proxy_requests_by_status",
        "gh_proxy_requests_by_type",
        "gh_proxy_requests_by_method",
        "gh_proxy_errors_total",
        "gh_proxy_info",
        "gh_proxy_uptime_seconds",
        "gh_proxy_active_requests",
        "gh_proxy_bytes_transferred_total",
        "gh_proxy_cache_hits_total",
        "gh_proxy_cache_misses_total",
    ] {
        assert!(names.contains(metric), "missing metric family {metric}");
    }
}
