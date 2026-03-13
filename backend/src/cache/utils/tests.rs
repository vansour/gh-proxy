use super::cacheability::{calculate_ttl, is_response_cacheable};
use super::directives::{
    extract_cache_directive, extract_shared_max_age, has_cache_control_directive,
};
use super::etag::generate_etag;
use crate::cache::config::CacheConfig;
use hyper::header;

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

    headers.insert(header::CACHE_CONTROL, "public".parse().unwrap());
    assert!(is_response_cacheable(200, &headers, &config));

    assert!(!is_response_cacheable(404, &headers, &config));

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

#[test]
fn calculate_ttl_prefers_shared_max_age_then_content_type_defaults() {
    let config = CacheConfig::default();
    let mut headers = hyper::HeaderMap::new();

    headers.insert(
        header::CACHE_CONTROL,
        format!("public, s-maxage={}", config.max_ttl_secs + 100)
            .parse()
            .unwrap(),
    );
    assert_eq!(
        calculate_ttl(&headers, &config, "/ignored").as_secs(),
        config.max_ttl_secs
    );

    headers.clear();
    headers.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    assert_eq!(
        calculate_ttl(&headers, &config, "/ignored"),
        config.get_ttl_for_content_type("text/plain")
    );
}
