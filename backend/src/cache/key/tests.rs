use super::{CacheKey, CacheKeyKind, request_variant_key};
use axum::http::{HeaderMap, header};

#[test]
fn test_cache_key_github() {
    let key = CacheKey::github("github.com", "/owner/repo/main/file.txt", Some("raw=true"));

    let s = key.to_cache_str();
    assert!(s.contains("gh"));
    assert!(s.contains("github.com"));

    let parsed = CacheKey::from_string(&s).unwrap();
    assert_eq!(parsed.kind, CacheKeyKind::GithubFile);
    assert_eq!(parsed.host, "github.com");
    assert_eq!(parsed.query, Some("raw=true".to_string()));
    assert_eq!(parsed.variant_key, None);
}

#[test]
fn test_cache_key_docker() {
    let key = CacheKey::docker_manifest("nginx", "latest");

    let s = key.to_cache_str();
    assert!(s.contains("manifest"));
    assert!(s.contains("nginx/latest"));

    let parsed = CacheKey::from_string(&s).unwrap();
    assert_eq!(parsed.kind, CacheKeyKind::DockerManifest);
    assert_eq!(parsed.variant_key, None);
}

#[test]
fn test_cache_key_round_trips_variant_key() {
    let key = CacheKey::generic_variant(
        "GET",
        "example.com",
        "/download",
        Some("raw=1"),
        Some(0xdead_beef_u64),
    );

    let parsed = CacheKey::from_string(&key.to_cache_str()).unwrap();

    assert_eq!(parsed.variant_key, Some(0xdead_beef_u64));
    assert_eq!(parsed.query, Some("raw=1".to_string()));
}

#[test]
fn test_request_variant_key_depends_on_accept_only() {
    let mut json_headers = HeaderMap::new();
    json_headers.insert(header::ACCEPT, "application/json".parse().unwrap());
    json_headers.insert(header::USER_AGENT, "curl/8.0".parse().unwrap());
    json_headers.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());

    let mut text_headers = HeaderMap::new();
    text_headers.insert(header::ACCEPT, "text/plain".parse().unwrap());
    text_headers.insert(header::USER_AGENT, "other-agent".parse().unwrap());
    text_headers.insert(header::ACCEPT_ENCODING, "br".parse().unwrap());

    assert_ne!(
        request_variant_key(&json_headers),
        request_variant_key(&text_headers)
    );
}

#[test]
fn test_request_variant_key_ignores_user_agent_and_accept_encoding() {
    let mut first = HeaderMap::new();
    first.insert(header::ACCEPT, "application/json".parse().unwrap());
    first.insert(header::USER_AGENT, "curl/8.0".parse().unwrap());
    first.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());

    let mut second = HeaderMap::new();
    second.insert(header::ACCEPT, "application/json".parse().unwrap());
    second.insert(header::USER_AGENT, "browser".parse().unwrap());
    second.insert(header::ACCEPT_ENCODING, "br".parse().unwrap());

    assert_eq!(request_variant_key(&first), request_variant_key(&second));
}

#[test]
fn test_request_variant_key_is_none_when_no_vary_headers_exist() {
    let headers = HeaderMap::new();

    assert_eq!(request_variant_key(&headers), None);
}
