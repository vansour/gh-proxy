//! Cache utility functions

use crate::cache::config::CacheConfig;
use axum::http::{HeaderName, HeaderValue};
use hyper::header;
use std::time::Duration;
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

/// Build CDN cache headers
pub fn build_cdn_cache_headers(
    _config: &CacheConfig,
    content_type: &str,
    is_cachable: bool,
) -> Vec<(HeaderName, HeaderValue)> {
    let mut headers = Vec::with_capacity(3);

    if !is_cachable || _config.strategy == crate::cache::config::CacheStrategy::Disabled {
        push_disabled_cache_headers(&mut headers);
        return headers;
    }

    let ttl = _config.get_ttl_for_content_type(content_type);
    let max_age = ttl.as_secs().min(_config.max_ttl_secs);

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

    // Accept is the only request-content negotiation input preserved by the proxy
    // that can safely affect shared-cache variants.
    headers.push((
        HeaderName::from_static("vary"),
        HeaderValue::from_static("Accept"),
    ));

    // Set CDN cache key tag (Cloudflare)
    headers.push((
        HeaderName::from_static("cf-cache-tag"),
        HeaderValue::from_static("gh-proxy-content"),
    ));

    headers
}

/// Check if response is cacheable
pub fn is_response_cacheable(
    status_code: u16,
    headers: &hyper::HeaderMap,
    _config: &CacheConfig,
) -> bool {
    // Only cache complete 200 OK responses. Partial content (206) and other
    // 2xx variants can be request-specific and are unsafe for this simple L1 cache.
    if status_code != 200 {
        return false;
    }

    // Check Cache-Control header
    if let Some(cache_control) = headers.get(header::CACHE_CONTROL)
        && let Ok(cc) = cache_control.to_str()
        && (has_cache_control_directive(cc, "no-store")
            || has_cache_control_directive(cc, "no-cache")
            || has_cache_control_directive(cc, "private"))
    {
        return false;
    }

    // Shared caches must never store responses that attempt to set client cookies.
    if headers.contains_key(header::SET_COOKIE) {
        return false;
    }

    // Encoded bodies are request-variant and can be served incorrectly by this
    // simple shared cache because the cache key does not currently vary by
    // Accept-Encoding.
    if headers.contains_key(header::CONTENT_ENCODING) {
        return false;
    }

    // RFC 9111: Vary: * means the response is selected by unspecified aspects
    // of the request and is unsuitable for shared caching.
    if let Some(vary) = headers.get(header::VARY)
        && let Ok(vary_value) = vary.to_str()
        && vary_value
            .split(',')
            .map(str::trim)
            .any(|token| token == "*")
    {
        return false;
    }

    // Check Content-Type
    if let Some(ct) = headers.get(header::CONTENT_TYPE)
        && let Ok(content_type) = ct.to_str()
    {
        // Don't cache streaming responses
        if content_type.contains("multipart/") {
            return false;
        }
    }

    true
}

/// Calculate response TTL
pub fn calculate_ttl(
    headers: &hyper::HeaderMap,
    config: &CacheConfig,
    _default_path: &str,
) -> Duration {
    // Prioritize upstream Cache-Control
    if let Some(cache_control) = headers.get(header::CACHE_CONTROL)
        && let Ok(cc) = cache_control.to_str()
        && let Some(max_age) = extract_shared_max_age(cc)
    {
        return Duration::from_secs(max_age.min(config.max_ttl_secs));
    }

    // Use default TTL based on Content-Type
    if let Some(ct) = headers.get(header::CONTENT_TYPE)
        && let Ok(content_type) = ct.to_str()
    {
        return config.get_ttl_for_content_type(content_type);
    }

    config.default_ttl()
}

fn extract_shared_max_age(cache_control: &str) -> Option<u64> {
    extract_cache_directive(cache_control, "s-maxage")
        .or_else(|| extract_cache_directive(cache_control, "max-age"))
}

fn has_cache_control_directive(cache_control: &str, directive: &str) -> bool {
    cache_control.split(',').any(|part| {
        let token = part.trim();
        token.eq_ignore_ascii_case(directive)
            || token
                .split_once('=')
                .map(|(name, _)| name.trim().eq_ignore_ascii_case(directive))
                .unwrap_or(false)
    })
}

/// Extract max-age from Cache-Control header
fn extract_cache_directive(cache_control: &str, directive: &str) -> Option<u64> {
    cache_control.split(',').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        if !name.trim().eq_ignore_ascii_case(directive) {
            return None;
        }

        value.trim().trim_matches('"').parse().ok()
    })
}

/// Generate ETag
pub fn generate_etag(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let hash = hasher.finish();

    format!("\"{:x}\"", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_max_age() {
        assert_eq!(
            extract_cache_directive("max-age=3600", "max-age"),
            Some(3600)
        );
        assert_eq!(
            extract_cache_directive("public, max-age=7200, must-revalidate", "max-age"),
            Some(7200)
        );
        assert_eq!(
            extract_shared_max_age("public, max-age=1800, s-maxage=7200"),
            Some(7200)
        );
        assert_eq!(extract_cache_directive("no-cache", "max-age"), None);
        assert_eq!(extract_cache_directive("max-age=invalid", "max-age"), None);
        assert_eq!(
            extract_cache_directive("public, S-MaxAge=14400", "s-maxage"),
            Some(14400)
        );
    }

    #[test]
    fn test_has_cache_control_directive() {
        assert!(has_cache_control_directive("public, no-store", "no-store"));
        assert!(has_cache_control_directive(
            "max-age=600, PRIVATE=\"set-cookie\"",
            "private"
        ));
        assert!(!has_cache_control_directive(
            "public, max-age=600",
            "private"
        ));
    }

    #[test]
    fn test_is_response_cacheable() {
        let config = CacheConfig::default();
        let mut headers = hyper::HeaderMap::new();

        // Cacheable: 200 OK
        headers.insert(header::CACHE_CONTROL, "public".parse().unwrap());
        assert!(is_response_cacheable(200, &headers, &config));

        // Not cacheable: 404
        assert!(!is_response_cacheable(404, &headers, &config));

        // Not cacheable: no-store
        headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        assert!(!is_response_cacheable(200, &headers, &config));
    }

    #[test]
    fn test_is_response_cacheable_rejects_set_cookie_and_content_encoding() {
        let config = CacheConfig::default();

        let mut cookie_headers = hyper::HeaderMap::new();
        cookie_headers.insert(header::SET_COOKIE, "session=secret".parse().unwrap());
        assert!(!is_response_cacheable(200, &cookie_headers, &config));

        let mut encoded_headers = hyper::HeaderMap::new();
        encoded_headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        assert!(!is_response_cacheable(200, &encoded_headers, &config));
    }

    #[test]
    fn test_is_response_cacheable_rejects_vary_star_and_partial_content() {
        let config = CacheConfig::default();

        let mut headers = hyper::HeaderMap::new();
        headers.insert(header::VARY, "Accept, *".parse().unwrap());
        assert!(!is_response_cacheable(200, &headers, &config));
        assert!(!is_response_cacheable(
            206,
            &hyper::HeaderMap::new(),
            &config
        ));
    }

    #[test]
    fn test_generate_etag() {
        let data = b"test data";
        let etag1 = generate_etag(data);
        let etag2 = generate_etag(data);
        assert_eq!(etag1, etag2);

        let different_data = b"different";
        let etag3 = generate_etag(different_data);
        assert_ne!(etag1, etag3);
    }
}
