use super::CachedResponse;
use crate::cache::key::CacheKey;
use axum::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use std::time::Duration;

#[test]
fn test_cached_response_expiry() {
    let key = CacheKey::generic("GET", "example.com", "/test", None);
    let response = CachedResponse::new(
        StatusCode::OK,
        HeaderMap::new(),
        Bytes::from("test"),
        Duration::from_secs(60),
        key,
    );
    assert!(!response.is_expired());
    assert!(!response.is_stale());
}

#[test]
fn test_matches_conditional() {
    let key = CacheKey::generic("GET", "example.com", "/test", None);
    let mut headers = HeaderMap::new();
    headers.insert("etag", "\"abc123\"".parse().unwrap());

    let response = CachedResponse::new(
        StatusCode::OK,
        headers,
        Bytes::from("test"),
        Duration::from_secs(60),
        key,
    );

    let mut if_none_match = HeaderMap::new();
    if_none_match.insert("if-none-match", "\"abc123\"".parse().unwrap());
    assert!(response.matches_conditional(&if_none_match));

    let mut if_none_match = HeaderMap::new();
    if_none_match.insert("if-none-match", "\"different\"".parse().unwrap());
    assert!(!response.matches_conditional(&if_none_match));
}
