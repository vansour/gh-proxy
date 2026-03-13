use super::directives::{extract_shared_max_age, has_cache_control_directive};
use crate::cache::config::CacheConfig;
use hyper::header;
use std::time::Duration;

pub fn is_response_cacheable(
    status_code: u16,
    headers: &hyper::HeaderMap,
    _config: &CacheConfig,
) -> bool {
    if status_code != 200 {
        return false;
    }

    if let Some(cache_control) = headers.get(header::CACHE_CONTROL)
        && let Ok(cache_control) = cache_control.to_str()
        && (has_cache_control_directive(cache_control, "no-store")
            || has_cache_control_directive(cache_control, "no-cache")
            || has_cache_control_directive(cache_control, "private"))
    {
        return false;
    }

    if headers.contains_key(header::SET_COOKIE) {
        return false;
    }

    if headers.contains_key(header::CONTENT_ENCODING) {
        return false;
    }

    if let Some(vary) = headers.get(header::VARY)
        && let Ok(vary_value) = vary.to_str()
        && vary_value
            .split(',')
            .map(str::trim)
            .any(|token| token == "*")
    {
        return false;
    }

    if let Some(content_type) = headers.get(header::CONTENT_TYPE)
        && let Ok(content_type) = content_type.to_str()
        && content_type.contains("multipart/")
    {
        return false;
    }

    true
}

pub fn calculate_ttl(
    headers: &hyper::HeaderMap,
    config: &CacheConfig,
    _default_path: &str,
) -> Duration {
    if let Some(cache_control) = headers.get(header::CACHE_CONTROL)
        && let Ok(cache_control) = cache_control.to_str()
        && let Some(max_age) = extract_shared_max_age(cache_control)
    {
        return Duration::from_secs(max_age.min(config.max_ttl_secs));
    }

    if let Some(content_type) = headers.get(header::CONTENT_TYPE)
        && let Ok(content_type) = content_type.to_str()
    {
        return config.get_ttl_for_content_type(content_type);
    }

    config.default_ttl()
}
