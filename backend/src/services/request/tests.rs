use super::{
    derive_public_base_url, detect_client_country_from_headers, detect_client_ip,
    detect_client_ip_from_headers, detect_client_protocol, ingress_host_allowed,
    normalize_public_base_url, ops_endpoint_access_allowed, origin_auth_allowed,
    trust_client_identity_headers,
};
use axum::{
    body::Body,
    http::{HeaderMap, Request},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

#[test]
fn detect_client_protocol_prefers_cf_visitor() {
    let req = Request::builder()
        .uri("/https://github.com/openai/gpt")
        .header("cf-visitor", r#"{"scheme":"https"}"#)
        .header("x-forwarded-proto", "http")
        .body(Body::empty())
        .expect("request");

    assert_eq!(detect_client_protocol(&req), "https");
}

#[test]
fn detect_client_protocol_accepts_forwarded_proto_case_insensitively() {
    let req = Request::builder()
        .uri("/https://github.com/openai/gpt")
        .header("x-forwarded-proto", "HTTP")
        .body(Body::empty())
        .expect("request");

    assert_eq!(detect_client_protocol(&req), "http");
}

#[test]
fn detect_client_protocol_falls_back_to_http_for_localhost() {
    let req = Request::builder()
        .uri("/https://github.com/openai/gpt")
        .header("host", "localhost:8080")
        .body(Body::empty())
        .expect("request");

    assert_eq!(detect_client_protocol(&req), "http");
}

#[test]
fn detect_client_ip_prefers_cf_connecting_ip() {
    let req = Request::builder()
        .uri("/https://github.com/openai/gpt")
        .header("cf-connecting-ip", "198.51.100.7")
        .header("x-forwarded-for", "203.0.113.1, 203.0.113.2")
        .body(Body::empty())
        .expect("request");

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
    assert_eq!(detect_client_ip(&req, Some(addr), true), "198.51.100.7");
}

#[test]
fn detect_client_ip_falls_back_to_forwarded_headers_and_socket() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        "203.0.113.8, 203.0.113.9".parse().unwrap(),
    );
    assert_eq!(
        detect_client_ip_from_headers(&headers, None, true),
        "203.0.113.8".to_string()
    );

    headers.clear();
    headers.insert(
        "forwarded",
        "for=\"[2001:db8:cafe::17]:4711\";proto=https"
            .parse()
            .unwrap(),
    );
    assert_eq!(
        detect_client_ip_from_headers(&headers, None, true),
        "2001:db8:cafe::17".to_string()
    );

    headers.clear();
    headers.insert("cf-connecting-ip", "not-an-ip".parse().unwrap());
    let socket_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let addr = SocketAddr::new(socket_ip, 8080);
    assert_eq!(
        detect_client_ip_from_headers(&headers, Some(addr), true),
        "127.0.0.1"
    );
}

#[test]
fn detect_client_country_reads_cloudflare_country() {
    let mut headers = HeaderMap::new();
    headers.insert("cf-ipcountry", "US".parse().unwrap());

    assert_eq!(
        detect_client_country_from_headers(&headers, true),
        Some("US".to_string())
    );
}

#[test]
fn detect_client_identity_headers_are_ignored_when_source_is_untrusted() {
    let mut headers = HeaderMap::new();
    headers.insert("cf-connecting-ip", "198.51.100.7".parse().unwrap());
    headers.insert(
        "x-forwarded-for",
        "203.0.113.8, 203.0.113.9".parse().unwrap(),
    );
    headers.insert("cf-ipcountry", "US".parse().unwrap());
    let socket_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));
    let addr = SocketAddr::new(socket_ip, 8443);

    assert_eq!(
        detect_client_ip_from_headers(&headers, Some(addr), false),
        "192.0.2.44"
    );
    assert_eq!(detect_client_country_from_headers(&headers, false), None);
}

#[test]
fn normalize_public_base_url_accepts_origin_only() {
    assert_eq!(
        normalize_public_base_url("https://proxy.example.com/").unwrap(),
        "https://proxy.example.com"
    );
    assert_eq!(
        normalize_public_base_url("http://proxy.example.com:8443").unwrap(),
        "http://proxy.example.com:8443"
    );
}

#[test]
fn normalize_public_base_url_rejects_paths_and_queries() {
    assert!(normalize_public_base_url("https://proxy.example.com/app").is_err());
    assert!(normalize_public_base_url("https://proxy.example.com/?x=1").is_err());
    assert!(normalize_public_base_url("ftp://proxy.example.com").is_err());
}

#[test]
fn derive_public_base_url_prefers_configured_value() {
    let req = Request::builder()
        .uri("/https://github.com/openai/gpt")
        .header("host", "evil.example")
        .body(Body::empty())
        .expect("request");

    assert_eq!(
        derive_public_base_url(&req, "https://proxy.example.com").as_deref(),
        Some("https://proxy.example.com")
    );
}

#[test]
fn derive_public_base_url_only_auto_derives_for_localhost() {
    let local_req = Request::builder()
        .uri("/https://github.com/openai/gpt")
        .header("host", "localhost:8080")
        .body(Body::empty())
        .expect("request");
    assert_eq!(
        derive_public_base_url(&local_req, "").as_deref(),
        Some("http://localhost:8080")
    );

    let remote_req = Request::builder()
        .uri("/https://github.com/openai/gpt")
        .header("host", "edge.example.com")
        .header("cf-visitor", r#"{"scheme":"https"}"#)
        .body(Body::empty())
        .expect("request");
    assert_eq!(derive_public_base_url(&remote_req, ""), None);
}

#[test]
fn ingress_host_allowed_accepts_loopback_and_configured_public_host() {
    let loopback_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
    let req = Request::builder()
        .uri("/api/config")
        .header("host", "evil.example")
        .body(Body::empty())
        .expect("request");
    assert!(ingress_host_allowed(
        &req,
        loopback_addr,
        "https://proxy.example.com"
    ));

    let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 443));
    let req = Request::builder()
        .uri("/api/config")
        .header("host", "proxy.example.com:443")
        .body(Body::empty())
        .expect("request");
    assert!(ingress_host_allowed(
        &req,
        remote_addr,
        "https://proxy.example.com"
    ));
}

#[test]
fn ingress_host_allowed_rejects_unexpected_remote_host() {
    let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 443));
    let req = Request::builder()
        .uri("/api/config")
        .header("host", "evil.example")
        .body(Body::empty())
        .expect("request");

    assert!(!ingress_host_allowed(
        &req,
        remote_addr,
        "https://proxy.example.com"
    ));
}

#[test]
fn ops_endpoint_access_only_allows_loopback_when_disabled() {
    let loopback_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9090));
    let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 9090));

    assert!(ops_endpoint_access_allowed(loopback_addr, false));
    assert!(!ops_endpoint_access_allowed(remote_addr, false));
    assert!(ops_endpoint_access_allowed(remote_addr, true));
}

#[test]
fn origin_auth_allowed_only_bypasses_for_loopback_or_matching_secret() {
    let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 443));
    let loopback_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
    let mut headers = HeaderMap::new();

    assert!(!origin_auth_allowed(
        &headers,
        remote_addr,
        "x-gh-proxy-origin-auth",
        "secret"
    ));

    headers.insert("x-gh-proxy-origin-auth", "secret".parse().unwrap());
    assert!(origin_auth_allowed(
        &headers,
        remote_addr,
        "x-gh-proxy-origin-auth",
        "secret"
    ));
    assert!(origin_auth_allowed(
        &HeaderMap::new(),
        loopback_addr,
        "x-gh-proxy-origin-auth",
        "secret"
    ));
    assert!(origin_auth_allowed(
        &HeaderMap::new(),
        remote_addr,
        "x-gh-proxy-origin-auth",
        ""
    ));
}

#[test]
fn trust_client_identity_headers_requires_loopback_or_origin_auth() {
    let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 443));
    let loopback_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));

    assert!(trust_client_identity_headers(Some(loopback_addr), false));
    assert!(trust_client_identity_headers(Some(remote_addr), true));
    assert!(!trust_client_identity_headers(Some(remote_addr), false));
    assert!(!trust_client_identity_headers(None, false));
}
