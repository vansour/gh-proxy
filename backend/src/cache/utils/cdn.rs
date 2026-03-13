use crate::cache::config::{CacheConfig, CacheStrategy};
use axum::http::{HeaderName, HeaderValue};
use tracing::warn;

fn push_disabled_cache_headers(headers: &mut Vec<(HeaderName, HeaderValue)>) {
    headers.push((
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    ));
    headers.push((
        HeaderName::from_static("pragma"),
        HeaderValue::from_static("no-cache"),
    ));
}

fn build_cache_control_header_value(max_age: u64) -> Option<HeaderValue> {
    let cache_control = format!(
        "public, max-age={}, s-maxage={}, stale-while-revalidate=300, stale-if-error=600",
        max_age / 2,
        max_age
    );

    HeaderValue::from_str(&cache_control).ok()
}

pub fn build_cdn_cache_headers(
    config: &CacheConfig,
    content_type: &str,
    is_cachable: bool,
) -> Vec<(HeaderName, HeaderValue)> {
    let mut headers = Vec::with_capacity(3);

    if !is_cachable || config.strategy == CacheStrategy::Disabled {
        push_disabled_cache_headers(&mut headers);
        return headers;
    }

    let ttl = config.get_ttl_for_content_type(content_type);
    let max_age = ttl.as_secs().min(config.max_ttl_secs);

    match build_cache_control_header_value(max_age) {
        Some(value) => headers.push((HeaderName::from_static("cache-control"), value)),
        None => {
            warn!(
                "Failed to build cache-control header for max_age={}",
                max_age
            );
            push_disabled_cache_headers(&mut headers);
            return headers;
        }
    }

    headers.push((
        HeaderName::from_static("vary"),
        HeaderValue::from_static("Accept"),
    ));
    headers.push((
        HeaderName::from_static("cf-cache-tag"),
        HeaderValue::from_static("gh-proxy-content"),
    ));

    headers
}
