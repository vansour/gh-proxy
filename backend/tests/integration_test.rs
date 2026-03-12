//! Integration tests

mod common;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use bytes::Bytes;
use gh_proxy::handlers::health::HealthStatus;
use gh_proxy::router;
use gh_proxy::services::client::build_client;
use http_body_util::BodyExt;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tower::ServiceExt;

#[tokio::test]
async fn test_proxy_caches_fallback_response() {
    common::setup();

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_route = Arc::clone(&hits);
    let upstream = common::spawn_mock(Router::new().route(
        "/cache.txt",
        get(move || {
            let hits = Arc::clone(&hits_for_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let mut headers = HeaderMap::new();
                headers.insert(
                    "cache-control",
                    HeaderValue::from_static("public, max-age=60"),
                );
                headers.insert("content-type", HeaderValue::from_static("text/plain"));
                headers.insert("content-length", HeaderValue::from_static("15"));
                (StatusCode::OK, headers, "cached response")
            }
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.cache.cacheable_patterns = vec!["*".to_string()];
    settings.cache.min_object_size = 1;
    let app = common::spawn_app(common::build_state(settings)).await;
    let target = format!("{}/{}/cache.txt", app.base_url, upstream.base_url);

    let (status1, headers1, body1) = common::get(&target).await;
    let (status2, headers2, body2) = common::get(&target).await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(body1, "cached response");
    assert_eq!(body2, "cached response");
    assert!(!headers1.contains_key("x-cache"));
    assert_eq!(
        headers2.get("x-cache").and_then(|v| v.to_str().ok()),
        Some("HIT from gh-proxy (L1)")
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_proxy_cache_varies_by_accept_header() {
    common::setup();

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_route = Arc::clone(&hits);
    let upstream = common::spawn_mock(Router::new().route(
        "/vary-by-accept",
        get(move |headers: HeaderMap| {
            let hits = Arc::clone(&hits_for_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);

                let accept = headers
                    .get(header::ACCEPT)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                let (content_type, body) = if accept.contains("application/json") {
                    ("application/json", r#"{"kind":"json"}"#)
                } else {
                    ("text/plain", "plain-body")
                };

                let mut response_headers = HeaderMap::new();
                response_headers.insert(
                    "cache-control",
                    HeaderValue::from_static("public, max-age=60"),
                );
                response_headers.insert(
                    "content-type",
                    HeaderValue::from_str(content_type).expect("content-type"),
                );
                response_headers.insert(
                    "content-length",
                    HeaderValue::from_str(&body.len().to_string()).expect("content-length"),
                );

                (StatusCode::OK, response_headers, body)
            }
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.cache.cacheable_patterns = vec!["*".to_string()];
    settings.cache.min_object_size = 1;
    let app = common::spawn_app(common::build_state(settings)).await;
    let target = format!("{}/{}/vary-by-accept", app.base_url, upstream.base_url);

    let (status1, headers1, body1) = common::request_with_headers(
        hyper::Method::GET,
        &target,
        &[("accept", "application/json")],
    )
    .await;
    let (status2, _, body2) =
        common::request_with_headers(hyper::Method::GET, &target, &[("accept", "text/plain")])
            .await;
    let (status3, headers3, body3) = common::request_with_headers(
        hyper::Method::GET,
        &target,
        &[("accept", "application/json")],
    )
    .await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(status3, StatusCode::OK);
    assert_eq!(body1, r#"{"kind":"json"}"#);
    assert_eq!(body2, "plain-body");
    assert_eq!(body3, r#"{"kind":"json"}"#);
    assert_eq!(
        headers1
            .get(header::VARY)
            .and_then(|value| value.to_str().ok()),
        Some("Accept")
    );
    assert_eq!(
        headers3
            .get("x-cache")
            .and_then(|value| value.to_str().ok()),
        Some("HIT from gh-proxy (L1)")
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_proxy_cache_does_not_vary_by_client_user_agent() {
    common::setup();

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_route = Arc::clone(&hits);
    let upstream = common::spawn_mock(Router::new().route(
        "/stable-by-ua",
        get(move |headers: HeaderMap| {
            let hits = Arc::clone(&hits_for_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);

                let upstream_user_agent = headers
                    .get(header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                let body = if upstream_user_agent.starts_with("gh-proxy/") {
                    "normalized-agent"
                } else {
                    "unexpected-agent"
                };

                let mut response_headers = HeaderMap::new();
                response_headers.insert(
                    "cache-control",
                    HeaderValue::from_static("public, max-age=60"),
                );
                response_headers.insert("content-type", HeaderValue::from_static("text/plain"));
                response_headers.insert(
                    "content-length",
                    HeaderValue::from_str(&body.len().to_string()).expect("content-length"),
                );

                (StatusCode::OK, response_headers, body)
            }
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.cache.cacheable_patterns = vec!["*".to_string()];
    settings.cache.min_object_size = 1;
    let app = common::spawn_app(common::build_state(settings)).await;
    let target = format!("{}/{}/stable-by-ua", app.base_url, upstream.base_url);

    let (status1, _, body1) =
        common::request_with_headers(hyper::Method::GET, &target, &[("user-agent", "curl/8.0")])
            .await;
    let (status2, headers2, body2) = common::request_with_headers(
        hyper::Method::GET,
        &target,
        &[("user-agent", "Mozilla/5.0")],
    )
    .await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(body1, "normalized-agent");
    assert_eq!(body2, "normalized-agent");
    assert_eq!(
        headers2
            .get("x-cache")
            .and_then(|value| value.to_str().ok()),
        Some("HIT from gh-proxy (L1)")
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_readyz_reports_registry_health() {
    common::setup();

    let upstream = common::spawn_mock(Router::new().route(
        "/v2/",
        get(|| async { StatusCode::OK }).head(|| async { StatusCode::OK }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.registry.default = upstream.base_url.clone();
    let app = common::spawn_app(common::build_state(settings)).await;

    let (liveness_status, _, liveness_body) =
        common::get(&format!("{}/healthz", app.base_url)).await;
    let liveness: HealthStatus = serde_json::from_slice(&liveness_body).expect("liveness json");
    assert_eq!(liveness_status, StatusCode::OK);
    assert!(liveness.checks.is_none());

    let (readiness_status, _, readiness_body) =
        common::get(&format!("{}/readyz", app.base_url)).await;
    let readiness: HealthStatus = serde_json::from_slice(&readiness_body).expect("readiness json");
    assert_eq!(readiness_status, StatusCode::OK);
    let registry = readiness.checks.expect("readiness checks").registry;
    assert!(registry.healthy);
    assert!(registry.message.unwrap_or_default().contains("reachable"));

    let (registry_status, _, registry_body) =
        common::get(&format!("{}/registry/healthz", app.base_url)).await;
    let registry_json: Value =
        serde_json::from_slice(&registry_body).expect("registry health json");
    assert_eq!(registry_status, StatusCode::OK);
    assert_eq!(registry_json["status"], "healthy");
}

#[tokio::test]
async fn test_readyz_returns_service_unavailable_when_registry_is_down() {
    common::setup();

    let mut settings = common::test_settings();
    settings.registry.default = "http://127.0.0.1:9".to_string();
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status, _, body) = common::get(&format!("{}/readyz", app.base_url)).await;
    let readiness: HealthStatus = serde_json::from_slice(&body).expect("readiness json");

    assert_eq!(status, StatusCode::OK);
    assert!(readiness.accepting_requests);
    let registry = readiness.checks.expect("readiness checks").registry;
    assert!(!registry.healthy);
    assert!(registry.message.unwrap_or_default().contains("unreachable"));
}

#[tokio::test]
async fn test_readyz_can_depend_on_registry_when_enabled() {
    common::setup();

    let mut settings = common::test_settings();
    settings.registry.default = "http://127.0.0.1:9".to_string();
    settings.registry.readiness_depends_on_registry = true;
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status, _, body) = common::get(&format!("{}/readyz", app.base_url)).await;
    let readiness: HealthStatus = serde_json::from_slice(&body).expect("readiness json");

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(readiness.accepting_requests);
    let registry = readiness.checks.expect("readiness checks").registry;
    assert!(!registry.healthy);
    assert!(registry.message.unwrap_or_default().contains("unreachable"));
}

#[tokio::test]
async fn test_registry_health_checks_are_cached_briefly() {
    common::setup();

    let health_hits = Arc::new(AtomicUsize::new(0));
    let health_hits_for_route = Arc::clone(&health_hits);
    let upstream = common::spawn_mock(Router::new().route(
        "/v2/",
        get(|| async { StatusCode::OK }).head(move || {
            let health_hits = Arc::clone(&health_hits_for_route);
            async move {
                health_hits.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.registry.default = upstream.base_url.clone();
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status1, _, _) = common::get(&format!("{}/readyz", app.base_url)).await;
    let (status2, _, _) = common::get(&format!("{}/registry/healthz", app.base_url)).await;
    let (status3, _, _) = common::get(&format!("{}/readyz", app.base_url)).await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(status3, StatusCode::OK);
    assert_eq!(health_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_api_config_exposes_runtime_settings() {
    common::setup();

    let mut settings = common::test_settings();
    settings.server.request_timeout_secs = 9;
    settings.rate_limit.max_requests = 42;
    settings.proxy.allowed_hosts.push("github.com".to_string());
    settings.registry.allowed_hosts = vec!["ghcr.io".to_string()];
    settings.debug.endpoints_enabled = true;
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status, _, body) = common::get(&format!("{}/api/config", app.base_url)).await;
    let config: Value = serde_json::from_slice(&body).expect("config json");

    assert_eq!(status, StatusCode::OK);
    assert_eq!(config["server"]["requestTimeoutSecs"], 9);
    assert_eq!(config["rateLimit"]["maxRequests"], 42);
    assert_eq!(config["shell"]["editor"], false);
    assert_eq!(
        config["shell"]["publicBaseUrl"],
        "https://proxy.example.com"
    );
    assert_eq!(config["debug"]["endpointsEnabled"], true);
    assert_eq!(config["cache"]["strategy"], "memory_only");
    assert_eq!(config["registry"]["default"], "registry-1.docker.io");
    assert_eq!(config["registry"]["readinessDependsOnRegistry"], false);
    assert!(
        config["registry"]["allowedHosts"]
            .as_array()
            .expect("registry allowed hosts array")
            .iter()
            .any(|value| value == "ghcr.io")
    );
    assert!(
        config["registry"]["allowedHosts"]
            .as_array()
            .expect("registry allowed hosts array")
            .iter()
            .any(|value| value == "registry-1.docker.io")
    );
    assert!(config["server"]["sizeLimit"].is_null());
    assert!(config["server"]["requestSizeLimit"].is_null());
    assert!(config["server"]["pool"].is_null());
    assert!(config["log"].is_null());
    assert!(config["cache"]["maxSizeBytes"].is_null());
    assert!(config["cache"]["cacheablePatterns"].is_null());
    assert!(
        config["proxy"]["allowedHosts"]
            .as_array()
            .expect("allowed hosts array")
            .iter()
            .any(|value| value == "github.com")
    );
}

#[tokio::test]
async fn test_api_config_sets_no_store_and_security_headers() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;
    let (status, headers, _) = common::get(&format!("{}/api/config", app.base_url)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store, no-cache, max-age=0")
    );
    assert_eq!(
        headers
            .get(header::PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
    assert_eq!(
        headers
            .get(header::EXPIRES)
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    assert_eq!(
        headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers
            .get("referrer-policy")
            .and_then(|value| value.to_str().ok()),
        Some("no-referrer")
    );
    assert_eq!(
        headers
            .get(header::X_FRAME_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("DENY")
    );
    assert!(headers.contains_key("permissions-policy"));
}

#[tokio::test]
async fn test_index_keeps_existing_cache_policy_and_adds_security_headers() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;
    let (status, headers, _) = common::get(&format!("{}/", app.base_url)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers
            .get(header::X_FRAME_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("DENY")
    );
}

#[tokio::test]
async fn test_metrics_endpoint_allows_loopback_by_default() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;
    let (status, headers, body) = common::get(&format!("{}/metrics", app.base_url)).await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store, no-cache, max-age=0")
    );
    assert!(body.contains("gh_proxy_requests_total"));
}

#[tokio::test]
async fn test_metrics_endpoint_rejects_remote_access_by_default() {
    common::setup();

    let state = common::build_state(common::test_settings());
    let app = router::create_router(state);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/metrics")
        .header("host", "proxy.example.com")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(remote_addr));

    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store, no-cache, max-age=0")
    );
    assert!(body.contains("Metrics endpoint is disabled"));
}

#[tokio::test]
async fn test_metrics_endpoint_can_be_enabled_for_remote_access() {
    common::setup();

    let mut settings = common::test_settings();
    settings.debug.metrics_enabled = true;
    let state = common::build_state(settings);
    let app = router::create_router(state);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/metrics")
        .header("host", "proxy.example.com")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(remote_addr));

    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("gh_proxy_requests_total"));
}

#[tokio::test]
async fn test_rate_limit_uses_cf_connecting_ip() {
    common::setup();

    let mut settings = common::test_settings();
    settings.rate_limit.max_requests = 1;
    let app = common::spawn_app(common::build_state(settings)).await;
    let url = format!("{}/api/config", app.base_url);

    let (status1, _, _) = common::request_with_headers(
        hyper::Method::GET,
        &url,
        &[("cf-connecting-ip", "198.51.100.10")],
    )
    .await;
    let (status2, _, _) = common::request_with_headers(
        hyper::Method::GET,
        &url,
        &[("cf-connecting-ip", "198.51.100.10")],
    )
    .await;
    let (status3, _, _) = common::request_with_headers(
        hyper::Method::GET,
        &url,
        &[("cf-connecting-ip", "198.51.100.11")],
    )
    .await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(status3, StatusCode::OK);
}

#[tokio::test]
async fn test_rate_limit_remote_requests_ignore_spoofed_cf_ip_without_origin_auth() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    settings.rate_limit.max_requests = 1;
    let state = common::build_state(settings);
    let app = router::create_router(state);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut request1 = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "proxy.example.com")
        .header("cf-connecting-ip", "203.0.113.1")
        .body(Body::empty())
        .expect("request");
    request1.extensions_mut().insert(ConnectInfo(remote_addr));

    let mut request2 = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "proxy.example.com")
        .header("cf-connecting-ip", "203.0.113.2")
        .body(Body::empty())
        .expect("request");
    request2.extensions_mut().insert(ConnectInfo(remote_addr));

    let response1 = app.clone().oneshot(request1).await.expect("response");
    let response2 = app.oneshot(request2).await.expect("response");

    assert_eq!(response1.status(), StatusCode::OK);
    assert_eq!(response2.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_rate_limit_remote_requests_trust_cf_ip_with_origin_auth() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    settings.ingress.auth_header_value = "secret".to_string();
    settings.rate_limit.max_requests = 1;
    let state = common::build_state(settings);
    let app = router::create_router(state);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut request1 = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "proxy.example.com")
        .header("x-gh-proxy-origin-auth", "secret")
        .header("cf-connecting-ip", "203.0.113.1")
        .body(Body::empty())
        .expect("request");
    request1.extensions_mut().insert(ConnectInfo(remote_addr));

    let mut request2 = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "proxy.example.com")
        .header("x-gh-proxy-origin-auth", "secret")
        .header("cf-connecting-ip", "203.0.113.2")
        .body(Body::empty())
        .expect("request");
    request2.extensions_mut().insert(ConnectInfo(remote_addr));

    let response1 = app.clone().oneshot(request1).await.expect("response");
    let response2 = app.oneshot(request2).await.expect("response");

    assert_eq!(response1.status(), StatusCode::OK);
    assert_eq!(response2.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_shell_editor_uses_configured_public_base_url() {
    common::setup();

    let upstream = common::spawn_mock(Router::new().route(
        "/install.sh",
        get(|| async {
            let body = "#!/bin/sh\ncurl -L https://github.com/owner/repo/releases/download/v1.0.0/app.tgz\n";
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("text/plain"));
            headers.insert("content-length", HeaderValue::from_str(&body.len().to_string()).unwrap());
            (StatusCode::OK, headers, body)
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.shell.editor = true;
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    let app = common::spawn_app(common::build_state(settings)).await;
    let target = format!("{}/{}/install.sh", app.base_url, upstream.base_url);

    let (status, _, body) =
        common::request_with_headers(hyper::Method::GET, &target, &[("host", "evil.example")])
            .await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(
        "https://proxy.example.com/https://github.com/owner/repo/releases/download/v1.0.0/app.tgz"
    ));
    assert!(!body.contains(
        "https://evil.example/https://github.com/owner/repo/releases/download/v1.0.0/app.tgz"
    ));
}

#[tokio::test]
async fn test_shell_editor_does_not_trust_remote_host_without_public_base_url() {
    common::setup();

    let upstream = common::spawn_mock(Router::new().route(
        "/install.sh",
        get(|| async {
            let body = "#!/bin/sh\ncurl -L https://github.com/owner/repo/releases/download/v1.0.0/app.tgz\n";
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("text/plain"));
            headers.insert("content-length", HeaderValue::from_str(&body.len().to_string()).unwrap());
            (StatusCode::OK, headers, body)
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.shell.editor = true;
    let app = common::spawn_app(common::build_state(settings)).await;
    let target = format!("{}/{}/install.sh", app.base_url, upstream.base_url);

    let (status, _, body) =
        common::request_with_headers(hyper::Method::GET, &target, &[("host", "evil.example")])
            .await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("https://github.com/owner/repo/releases/download/v1.0.0/app.tgz"));
    assert!(!body.contains(
        "https://evil.example/https://github.com/owner/repo/releases/download/v1.0.0/app.tgz"
    ));
}

#[tokio::test]
async fn test_ingress_host_guard_rejects_unexpected_remote_host() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "evil.example")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(remote_addr));

    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("Origin Host Not Allowed"));
    assert!(body.contains("shell.public_base_url"));
}

#[tokio::test]
async fn test_ingress_host_guard_accepts_configured_public_host() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "proxy.example.com")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(remote_addr));

    let response = app.oneshot(request).await.expect("response");
    let status = response.status();

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_ingress_origin_auth_rejects_remote_requests_without_secret() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    settings.ingress.auth_header_value = "secret".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "proxy.example.com")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(remote_addr));

    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("Origin Access Authentication Failed"));
    assert!(body.contains("x-gh-proxy-origin-auth"));
}

#[tokio::test]
async fn test_ingress_origin_auth_accepts_remote_requests_with_secret() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    settings.ingress.auth_header_value = "secret".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "proxy.example.com")
        .header("x-gh-proxy-origin-auth", "secret")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(remote_addr));

    let response = app.oneshot(request).await.expect("response");
    let status = response.status();

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_ingress_origin_auth_keeps_loopback_access_without_secret_header() {
    common::setup();

    let mut settings = common::test_settings();
    settings.ingress.auth_header_value = "secret".to_string();
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status, _, _) = common::get(&format!("{}/api/config", app.base_url)).await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_cross_origin_requests_are_not_cors_enabled() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;
    let url = format!("{}/api/config", app.base_url);

    let (status, headers, _) = common::request_with_headers(
        hyper::Method::GET,
        &url,
        &[("origin", "https://evil.example")],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key("access-control-allow-origin"));
    assert!(!headers.contains_key("access-control-allow-credentials"));
}

#[tokio::test]
async fn test_proxy_strips_client_forwarding_headers_before_upstream() {
    common::setup();

    let upstream = common::spawn_mock(Router::new().route(
        "/forwarded-headers",
        get(|headers: HeaderMap| async move {
            let leaked = [
                "cf-connecting-ip",
                "cf-ipcountry",
                "cf-ray",
                "cf-visitor",
                "cookie",
                "forwarded",
                "origin",
                "referer",
                "sec-fetch-site",
                "x-gh-proxy-origin-auth",
                "x-forwarded-for",
                "x-forwarded-proto",
                "x-real-ip",
            ]
            .into_iter()
            .filter(|name| headers.contains_key(*name))
            .collect::<Vec<_>>();

            if leaked.is_empty() {
                (StatusCode::OK, "clean").into_response()
            } else {
                (StatusCode::BAD_REQUEST, leaked.join(",")).into_response()
            }
        }),
    ))
    .await;

    let app = common::spawn_app(common::build_state(common::test_settings())).await;
    let target = format!("{}/{}/forwarded-headers", app.base_url, upstream.base_url);
    let headers = [
        ("cf-connecting-ip", "198.51.100.10"),
        ("cf-ipcountry", "US"),
        ("cf-ray", "abc123"),
        ("cf-visitor", r#"{"scheme":"https"}"#),
        ("forwarded", "for=198.51.100.10;proto=https"),
        ("cookie", "session=secret"),
        ("origin", "https://evil.example"),
        ("referer", "https://evil.example/app"),
        ("sec-fetch-site", "cross-site"),
        ("x-gh-proxy-origin-auth", "secret"),
        ("x-forwarded-for", "198.51.100.10, 203.0.113.7"),
        ("x-forwarded-proto", "https"),
        ("x-real-ip", "198.51.100.10"),
    ];

    let (status, _, body) =
        common::request_with_headers(hyper::Method::GET, &target, &headers).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "clean");
}

#[tokio::test]
async fn test_debug_blob_info_is_disabled_by_default() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;

    let (status, _, body) = common::get(&format!("{}/debug/blob-info", app.base_url)).await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("Debug endpoints are disabled"));
}

#[tokio::test]
async fn test_debug_blob_info_can_be_enabled() {
    common::setup();

    let mut settings = common::test_settings();
    settings.debug.endpoints_enabled = true;
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status, _, body) = common::get(&format!("{}/debug/blob-info", app.base_url)).await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("missing 'name' query parameter"));
}

#[tokio::test]
async fn test_api_stats_exposes_cache_metrics() {
    common::setup();

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_route = Arc::clone(&hits);
    let upstream = common::spawn_mock(Router::new().route(
        "/stats-cache.txt",
        get(move || {
            let hits = Arc::clone(&hits_for_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let mut headers = HeaderMap::new();
                headers.insert(
                    "cache-control",
                    HeaderValue::from_static("public, max-age=60"),
                );
                headers.insert("content-type", HeaderValue::from_static("text/plain"));
                headers.insert("content-length", HeaderValue::from_static("13"));
                (StatusCode::OK, headers, "cache metrics")
            }
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.cache.cacheable_patterns = vec!["*".to_string()];
    settings.cache.min_object_size = 1;
    let app = common::spawn_app(common::build_state(settings)).await;
    let target = format!("{}/{}/stats-cache.txt", app.base_url, upstream.base_url);

    let _ = common::get(&target).await;
    let _ = common::get(&target).await;

    let (status, _, body) = common::get(&format!("{}/api/stats", app.base_url)).await;
    let stats: Value = serde_json::from_slice(&body).expect("stats json");

    assert_eq!(status, StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(stats["cache"]["strategy"], "memory_only");
    assert_eq!(stats["cache"]["entryCount"], 1);
    assert_eq!(stats["cache"]["hits"], 1);
    assert_eq!(stats["cache"]["misses"], 1);
    assert!(stats["cache"]["hitRate"].as_f64().unwrap_or_default() > 0.0);
    assert!(stats["cache"]["weightedSize"].as_u64().unwrap_or_default() > 0);
}

#[tokio::test]
async fn test_api_stats_total_requests_include_fallback_cache_hits() {
    common::setup();

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_route = Arc::clone(&hits);
    let upstream = common::spawn_mock(Router::new().route(
        "/count-cache.txt",
        get(move || {
            let hits = Arc::clone(&hits_for_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let mut headers = HeaderMap::new();
                headers.insert(
                    "cache-control",
                    HeaderValue::from_static("public, max-age=60"),
                );
                headers.insert("content-type", HeaderValue::from_static("text/plain"));
                headers.insert("content-length", HeaderValue::from_static("11"));
                (StatusCode::OK, headers, "cache total")
            }
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.cache.cacheable_patterns = vec!["*".to_string()];
    settings.cache.min_object_size = 1;
    let app = common::spawn_app(common::build_state(settings)).await;
    let target = format!("{}/{}/count-cache.txt", app.base_url, upstream.base_url);

    let (_, _, before_body) = common::get(&format!("{}/api/stats", app.base_url)).await;
    let before: Value = serde_json::from_slice(&before_body).expect("before stats json");

    let (status1, _, body1) = common::get(&target).await;
    let (status2, headers2, body2) = common::get(&target).await;
    let (stats_status, _, after_body) = common::get(&format!("{}/api/stats", app.base_url)).await;
    let after: Value = serde_json::from_slice(&after_body).expect("after stats json");

    let total_delta = after["server"]["total_requests"]
        .as_u64()
        .unwrap_or_default()
        .saturating_sub(
            before["server"]["total_requests"]
                .as_u64()
                .unwrap_or_default(),
        );

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(stats_status, StatusCode::OK);
    assert_eq!(body1, "cache total");
    assert_eq!(body2, "cache total");
    assert_eq!(
        headers2
            .get("x-cache")
            .and_then(|value| value.to_str().ok()),
        Some("HIT from gh-proxy (L1)")
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(total_delta >= 3);
}

#[tokio::test]
async fn test_api_stats_total_requests_include_early_proxy_rejections() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;

    let (_, _, before_body) = common::get(&format!("{}/api/stats", app.base_url)).await;
    let before: Value = serde_json::from_slice(&before_body).expect("before stats json");

    let (github_post_status, _, _) = common::request(
        hyper::Method::POST,
        &format!("{}/github/owner/repo/main/file.txt", app.base_url),
    )
    .await;
    let (github_path_status, _, _) =
        common::get(&format!("{}/github/owner/repo", app.base_url)).await;
    let (fallback_post_status, _, _) = common::request(
        hyper::Method::POST,
        &format!(
            "{}/https://github.com/owner/repo/blob/main/file.txt",
            app.base_url
        ),
    )
    .await;

    let (stats_status, _, after_body) = common::get(&format!("{}/api/stats", app.base_url)).await;
    let after: Value = serde_json::from_slice(&after_body).expect("after stats json");

    let total_delta = after["server"]["total_requests"]
        .as_u64()
        .unwrap_or_default()
        .saturating_sub(
            before["server"]["total_requests"]
                .as_u64()
                .unwrap_or_default(),
        );
    let github_delta = after["requests"]["byType"]["github"]
        .as_u64()
        .unwrap_or_default()
        .saturating_sub(
            before["requests"]["byType"]["github"]
                .as_u64()
                .unwrap_or_default(),
        );
    let fallback_delta = after["requests"]["byType"]["fallback"]
        .as_u64()
        .unwrap_or_default()
        .saturating_sub(
            before["requests"]["byType"]["fallback"]
                .as_u64()
                .unwrap_or_default(),
        );
    let four_xx_delta = after["requests"]["byStatus"]["4xx"]
        .as_u64()
        .unwrap_or_default()
        .saturating_sub(
            before["requests"]["byStatus"]["4xx"]
                .as_u64()
                .unwrap_or_default(),
        );

    assert_eq!(github_post_status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(github_path_status, StatusCode::BAD_REQUEST);
    assert_eq!(fallback_post_status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(stats_status, StatusCode::OK);
    assert!(total_delta >= 4);
    assert!(github_delta >= 2);
    assert!(fallback_delta >= 1);
    assert!(four_xx_delta >= 3);
}

#[tokio::test]
async fn test_api_stats_exposes_request_breakdowns() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;

    let (_, _, before_body) = common::get(&format!("{}/api/stats", app.base_url)).await;
    let before: Value = serde_json::from_slice(&before_body).expect("before stats json");

    let _ = common::get(&format!("{}/healthz", app.base_url)).await;
    let _ = common::get(&format!("{}/v2/", app.base_url)).await;
    let _ = common::get(&format!("{}/api/config", app.base_url)).await;
    let _ = common::request(
        hyper::Method::POST,
        &format!("{}/github/owner/repo/main/file.txt", app.base_url),
    )
    .await;

    let (status, _, after_body) = common::get(&format!("{}/api/stats", app.base_url)).await;
    let after: Value = serde_json::from_slice(&after_body).expect("after stats json");

    let delta = |section: &str, key: &str| -> u64 {
        let after = after[section][key].as_u64().unwrap_or_default();
        let before = before[section][key].as_u64().unwrap_or_default();
        after.saturating_sub(before)
    };
    let nested_delta = |section: &str, subsection: &str, key: &str| -> u64 {
        let after = after[section][subsection][key].as_u64().unwrap_or_default();
        let before = before[section][subsection][key]
            .as_u64()
            .unwrap_or_default();
        after.saturating_sub(before)
    };

    assert_eq!(status, StatusCode::OK);
    assert!(nested_delta("requests", "byType", "infra") >= 1);
    assert!(nested_delta("requests", "byType", "registry") >= 1);
    assert!(nested_delta("requests", "byType", "github") >= 1);
    assert!(nested_delta("requests", "byType", "api") >= 2);
    assert!(nested_delta("requests", "byMethod", "GET") >= 4);
    assert!(nested_delta("requests", "byMethod", "POST") >= 1);
    assert!(nested_delta("requests", "byStatus", "2xx") >= 3);
    assert!(nested_delta("requests", "byStatus", "4xx") >= 1);
    assert!(delta("errors", "method_not_allowed") >= 1);
}

#[tokio::test]
async fn test_registry_manifest_and_blob_proxy() {
    common::setup();

    let manifest =
        r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}"#;
    let upstream = common::spawn_mock(
        Router::new()
            .route(
                "/v2/",
                get(|| async { StatusCode::OK }).head(|| async { StatusCode::OK }),
            )
            .route(
                "/v2/library/test/manifests/latest",
                get({
                    let manifest = manifest.to_string();
                    move || {
                        let manifest = manifest.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert(
                                "content-type",
                                HeaderValue::from_static(
                                    "application/vnd.docker.distribution.manifest.v2+json",
                                ),
                            );
                            headers.insert(
                                "content-length",
                                HeaderValue::from_str(&manifest.len().to_string()).unwrap(),
                            );
                            (StatusCode::OK, headers, manifest)
                        }
                    }
                })
                .head(|| async {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        "content-type",
                        HeaderValue::from_static(
                            "application/vnd.docker.distribution.manifest.v2+json",
                        ),
                    );
                    headers.insert("content-length", HeaderValue::from_static("88"));
                    (StatusCode::OK, headers)
                }),
            )
            .route(
                "/v2/library/test/blobs/sha256:abc",
                get(|| async {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        "content-type",
                        HeaderValue::from_static("application/octet-stream"),
                    );
                    headers.insert("content-length", HeaderValue::from_static("4"));
                    (StatusCode::OK, headers, "blob")
                })
                .head(|| async {
                    let mut headers = HeaderMap::new();
                    headers.insert("content-length", HeaderValue::from_static("4"));
                    (StatusCode::OK, headers)
                }),
            ),
    )
    .await;

    let mut settings = common::test_settings();
    settings.registry.default = upstream.base_url.clone();
    let app = common::spawn_app(common::build_state(settings)).await;

    let (manifest_status, manifest_headers, manifest_body) = common::get(&format!(
        "{}/v2/library/test/manifests/latest",
        app.base_url
    ))
    .await;
    assert_eq!(manifest_status, StatusCode::OK);
    assert_eq!(
        manifest_headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/vnd.docker.distribution.manifest.v2+json")
    );
    assert_eq!(manifest_body, manifest);

    let (blob_status, _, blob_body) = common::get(&format!(
        "{}/v2/library/test/blobs/sha256:abc",
        app.base_url
    ))
    .await;
    assert_eq!(blob_status, StatusCode::OK);
    assert_eq!(blob_body, "blob");
}

#[tokio::test]
async fn test_registry_manifest_get_uses_l1_cache() {
    common::setup();

    let manifest_hits = Arc::new(AtomicUsize::new(0));
    let manifest_hits_for_route = Arc::clone(&manifest_hits);
    let manifest =
        r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}"#;
    let upstream = common::spawn_mock(
        Router::new()
            .route(
                "/v2/",
                get(|| async { StatusCode::OK }).head(|| async { StatusCode::OK }),
            )
            .route(
                "/v2/library/test/manifests/latest",
                get({
                    let manifest = manifest.to_string();
                    move || {
                        let manifest = manifest.clone();
                        let manifest_hits = Arc::clone(&manifest_hits_for_route);
                        async move {
                            manifest_hits.fetch_add(1, Ordering::SeqCst);
                            let mut headers = HeaderMap::new();
                            headers.insert(
                                "content-type",
                                HeaderValue::from_static(
                                    "application/vnd.docker.distribution.manifest.v2+json",
                                ),
                            );
                            headers.insert(
                                "content-length",
                                HeaderValue::from_str(&manifest.len().to_string()).unwrap(),
                            );
                            headers.insert(
                                "cache-control",
                                HeaderValue::from_static("public, max-age=60"),
                            );
                            (StatusCode::OK, headers, manifest)
                        }
                    }
                }),
            ),
    )
    .await;

    let mut settings = common::test_settings();
    settings.registry.default = upstream.base_url.clone();
    settings.cache.min_object_size = 1;
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status1, headers1, body1) = common::get(&format!(
        "{}/v2/library/test/manifests/latest",
        app.base_url
    ))
    .await;
    let (status2, headers2, body2) = common::get(&format!(
        "{}/v2/library/test/manifests/latest",
        app.base_url
    ))
    .await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(body1, manifest);
    assert_eq!(body2, manifest);
    assert!(!headers1.contains_key("x-cache"));
    assert_eq!(
        headers2
            .get("x-cache")
            .and_then(|value| value.to_str().ok()),
        Some("HIT from gh-proxy (L1)")
    );
    assert_eq!(manifest_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_registry_small_blob_get_uses_l1_cache() {
    common::setup();

    let blob_hits = Arc::new(AtomicUsize::new(0));
    let blob_hits_for_route = Arc::clone(&blob_hits);
    let upstream = common::spawn_mock(
        Router::new()
            .route(
                "/v2/",
                get(|| async { StatusCode::OK }).head(|| async { StatusCode::OK }),
            )
            .route(
                "/v2/library/test/blobs/sha256:cached",
                get(move || {
                    let blob_hits = Arc::clone(&blob_hits_for_route);
                    async move {
                        blob_hits.fetch_add(1, Ordering::SeqCst);
                        let mut headers = HeaderMap::new();
                        headers.insert(
                            "content-type",
                            HeaderValue::from_static("application/octet-stream"),
                        );
                        headers.insert("content-length", HeaderValue::from_static("11"));
                        headers.insert(
                            "cache-control",
                            HeaderValue::from_static("public, max-age=60"),
                        );
                        (StatusCode::OK, headers, "cached-blob")
                    }
                }),
            ),
    )
    .await;

    let mut settings = common::test_settings();
    settings.registry.default = upstream.base_url.clone();
    settings.cache.min_object_size = 1;
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status1, headers1, body1) = common::get(&format!(
        "{}/v2/library/test/blobs/sha256:cached",
        app.base_url
    ))
    .await;
    let (status2, headers2, body2) = common::get(&format!(
        "{}/v2/library/test/blobs/sha256:cached",
        app.base_url
    ))
    .await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(body1, "cached-blob");
    assert_eq!(body2, "cached-blob");
    assert!(!headers1.contains_key("x-cache"));
    assert_eq!(
        headers2
            .get("x-cache")
            .and_then(|value| value.to_str().ok()),
        Some("HIT from gh-proxy (L1)")
    );
    assert_eq!(blob_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_registry_head_requests_retry_with_bearer_token() {
    common::setup();

    let token_service = common::spawn_mock(Router::new().route(
        "/token",
        get(|| async {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("application/json"));
            (
                StatusCode::OK,
                headers,
                r#"{"token":"test-token","expires_in":60}"#,
            )
        }),
    ))
    .await;

    let challenge = format!(
        "Bearer realm=\"{}/token\",service=\"registry.test\",scope=\"repository:library/test:pull\"",
        token_service.base_url
    );
    let manifest_head_hits = Arc::new(AtomicUsize::new(0));
    let blob_head_hits = Arc::new(AtomicUsize::new(0));

    let upstream = common::spawn_mock(
        Router::new()
            .route(
                "/v2/",
                get(|| async { StatusCode::OK }).head(|| async { StatusCode::OK }),
            )
            .route(
                "/v2/library/test/manifests/latest",
                get(|| async { StatusCode::METHOD_NOT_ALLOWED }).head({
                    let challenge = challenge.clone();
                    let manifest_head_hits = Arc::clone(&manifest_head_hits);
                    move |headers: HeaderMap| {
                        let challenge = challenge.clone();
                        let manifest_head_hits = Arc::clone(&manifest_head_hits);
                        async move {
                            manifest_head_hits.fetch_add(1, Ordering::SeqCst);
                            if headers.get(header::AUTHORIZATION)
                                == Some(&HeaderValue::from_static("Bearer test-token"))
                            {
                                let mut resp_headers = HeaderMap::new();
                                resp_headers.insert(
                                    "content-type",
                                    HeaderValue::from_static(
                                        "application/vnd.docker.distribution.manifest.v2+json",
                                    ),
                                );
                                resp_headers
                                    .insert("content-length", HeaderValue::from_static("88"));
                                (StatusCode::OK, resp_headers).into_response()
                            } else {
                                let mut resp_headers = HeaderMap::new();
                                resp_headers.insert(
                                    header::WWW_AUTHENTICATE,
                                    HeaderValue::from_str(&challenge).expect("challenge header"),
                                );
                                (StatusCode::UNAUTHORIZED, resp_headers).into_response()
                            }
                        }
                    }
                }),
            )
            .route(
                "/v2/library/test/blobs/sha256:abc",
                get(|| async { StatusCode::METHOD_NOT_ALLOWED }).head({
                    let challenge = challenge.clone();
                    let blob_head_hits = Arc::clone(&blob_head_hits);
                    move |headers: HeaderMap| {
                        let challenge = challenge.clone();
                        let blob_head_hits = Arc::clone(&blob_head_hits);
                        async move {
                            blob_head_hits.fetch_add(1, Ordering::SeqCst);
                            if headers.get(header::AUTHORIZATION)
                                == Some(&HeaderValue::from_static("Bearer test-token"))
                            {
                                let mut resp_headers = HeaderMap::new();
                                resp_headers
                                    .insert("content-length", HeaderValue::from_static("4"));
                                (StatusCode::OK, resp_headers).into_response()
                            } else {
                                let mut resp_headers = HeaderMap::new();
                                resp_headers.insert(
                                    header::WWW_AUTHENTICATE,
                                    HeaderValue::from_str(&challenge).expect("challenge header"),
                                );
                                (StatusCode::UNAUTHORIZED, resp_headers).into_response()
                            }
                        }
                    }
                }),
            ),
    )
    .await;

    let mut settings = common::test_settings();
    settings.registry.default = upstream.base_url.clone();
    let app = common::spawn_app(common::build_state(settings)).await;

    let (manifest_status, manifest_headers, manifest_body) = common::request(
        hyper::Method::HEAD,
        &format!("{}/v2/library/test/manifests/latest", app.base_url),
    )
    .await;
    assert_eq!(manifest_status, StatusCode::OK);
    assert_eq!(
        manifest_headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/vnd.docker.distribution.manifest.v2+json")
    );
    assert_eq!(
        manifest_headers
            .get("content-length")
            .and_then(|value| value.to_str().ok()),
        Some("88")
    );
    assert!(manifest_body.is_empty());

    let (blob_status, blob_headers, blob_body) = common::request(
        hyper::Method::HEAD,
        &format!("{}/v2/library/test/blobs/sha256:abc", app.base_url),
    )
    .await;
    assert_eq!(blob_status, StatusCode::OK);
    assert_eq!(
        blob_headers
            .get("content-length")
            .and_then(|value| value.to_str().ok()),
        Some("4")
    );
    assert!(blob_body.is_empty());

    assert_eq!(manifest_head_hits.load(Ordering::SeqCst), 2);
    assert_eq!(blob_head_hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_registry_proxy_is_read_only() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;

    let (post_status, _, post_body) = common::request(
        hyper::Method::POST,
        &format!("{}/v2/library/test/blobs/uploads/", app.base_url),
    )
    .await;
    let (patch_status, _, patch_body) = common::request(
        hyper::Method::PATCH,
        &format!("{}/v2/library/test/blobs/uploads/123", app.base_url),
    )
    .await;
    let (put_status, _, put_body) = common::request(
        hyper::Method::PUT,
        &format!("{}/v2/library/test/blobs/uploads/123", app.base_url),
    )
    .await;

    assert_eq!(post_status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(patch_status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(put_status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(String::from_utf8_lossy(&post_body).contains("Read-only registry proxy"));
    assert!(String::from_utf8_lossy(&patch_body).contains("Read-only registry proxy"));
    assert!(String::from_utf8_lossy(&put_body).contains("Read-only registry proxy"));
}

#[tokio::test]
async fn test_registry_blob_stream_updates_active_request_metrics() {
    common::setup();

    let blob_hits = Arc::new(AtomicUsize::new(0));
    let release_blob = Arc::new(Notify::new());
    let upstream = common::spawn_mock(
        Router::new()
            .route(
                "/v2/",
                get(|| async { StatusCode::OK }).head(|| async { StatusCode::OK }),
            )
            .route(
                "/v2/library/test/blobs/sha256:stream",
                get({
                    let blob_hits = Arc::clone(&blob_hits);
                    let release_blob = Arc::clone(&release_blob);
                    move || {
                        let blob_hits = Arc::clone(&blob_hits);
                        let release_blob = Arc::clone(&release_blob);
                        async move {
                            blob_hits.fetch_add(1, Ordering::SeqCst);
                            let mut headers = HeaderMap::new();
                            headers.insert(
                                "content-type",
                                HeaderValue::from_static("application/octet-stream"),
                            );
                            headers.insert("content-length", HeaderValue::from_static("11"));
                            let body = Body::from_stream(futures_util::stream::once(async move {
                                release_blob.notified().await;
                                Ok::<Bytes, std::io::Error>(Bytes::from_static(b"stream-body"))
                            }));
                            (StatusCode::OK, headers, body)
                        }
                    }
                }),
            ),
    )
    .await;

    let mut settings = common::test_settings();
    settings.registry.default = upstream.base_url.clone();
    let app = common::spawn_app(common::build_state(settings)).await;

    let client = build_client(&common::test_settings().server);
    let request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(format!(
            "{}/v2/library/test/blobs/sha256:stream",
            app.base_url
        ))
        .body(axum::body::Body::empty())
        .expect("blob request");

    let (stats_before_status, _, stats_before_body) =
        common::get(&format!("{}/api/stats", app.base_url)).await;
    let stats_before: Value =
        serde_json::from_slice(&stats_before_body).expect("stats before json");
    assert_eq!(stats_before_status, StatusCode::OK);

    let response = client
        .request(request)
        .await
        .expect("registry blob response");
    assert_eq!(response.status(), StatusCode::OK);

    let wait_start = tokio::time::Instant::now();
    while blob_hits.load(Ordering::SeqCst) != 1 {
        assert!(wait_start.elapsed() < Duration::from_secs(1));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let (stats_active_status, _, stats_active_body) =
        common::get(&format!("{}/api/stats", app.base_url)).await;
    let stats_active: Value =
        serde_json::from_slice(&stats_active_body).expect("stats active json");
    let (health_status, _, health_body) = common::get(&format!("{}/healthz", app.base_url)).await;
    let health: HealthStatus = serde_json::from_slice(&health_body).expect("health json");

    assert_eq!(stats_active_status, StatusCode::OK);
    assert_eq!(health_status, StatusCode::OK);
    assert!(
        stats_active["server"]["active_requests"]
            .as_i64()
            .unwrap_or_default()
            >= 1
    );
    assert!(health.active_requests >= 1);

    release_blob.notify_waiters();
    let body = BodyExt::collect(response.into_body())
        .await
        .expect("read registry blob body")
        .to_bytes();
    assert_eq!(body, Bytes::from_static(b"stream-body"));

    let (stats_after_status, _, stats_after_body) =
        common::get(&format!("{}/api/stats", app.base_url)).await;
    let stats_after: Value = serde_json::from_slice(&stats_after_body).expect("stats after json");
    let bytes_delta = stats_after["server"]["bytes_transferred"]
        .as_u64()
        .unwrap_or_default()
        .saturating_sub(
            stats_before["server"]["bytes_transferred"]
                .as_u64()
                .unwrap_or_default(),
        );

    assert_eq!(stats_after_status, StatusCode::OK);
    assert!(bytes_delta >= 11);
    assert_eq!(blob_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_registry_blob_requests_respect_download_semaphore() {
    common::setup();

    let blob_hits = Arc::new(AtomicUsize::new(0));
    let release_first_blob = Arc::new(Notify::new());
    let upstream = common::spawn_mock(
        Router::new()
            .route(
                "/v2/",
                get(|| async { StatusCode::OK }).head(|| async { StatusCode::OK }),
            )
            .route(
                "/v2/library/test/blobs/sha256:block",
                get({
                    let blob_hits = Arc::clone(&blob_hits);
                    let release_first_blob = Arc::clone(&release_first_blob);
                    move || {
                        let blob_hits = Arc::clone(&blob_hits);
                        let release_first_blob = Arc::clone(&release_first_blob);
                        async move {
                            let hit_index = blob_hits.fetch_add(1, Ordering::SeqCst) + 1;
                            let mut headers = HeaderMap::new();
                            headers.insert(
                                "content-type",
                                HeaderValue::from_static("application/octet-stream"),
                            );

                            let body = if hit_index == 1 {
                                headers.insert("content-length", HeaderValue::from_static("5"));
                                Body::from_stream(futures_util::stream::once(async move {
                                    release_first_blob.notified().await;
                                    Ok::<Bytes, std::io::Error>(Bytes::from_static(b"first"))
                                }))
                            } else {
                                headers.insert("content-length", HeaderValue::from_static("6"));
                                Body::from_stream(futures_util::stream::once(async {
                                    Ok::<Bytes, std::io::Error>(Bytes::from_static(b"second"))
                                }))
                            };

                            (StatusCode::OK, headers, body)
                        }
                    }
                }),
            ),
    )
    .await;

    let mut settings = common::test_settings();
    settings.registry.default = upstream.base_url.clone();
    settings.server.max_concurrent_requests = 1;
    let app = common::spawn_app(common::build_state(settings)).await;

    let client = build_client(&common::test_settings().server);
    let first_request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(format!(
            "{}/v2/library/test/blobs/sha256:block",
            app.base_url
        ))
        .body(axum::body::Body::empty())
        .expect("first registry request");
    let second_request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(format!(
            "{}/v2/library/test/blobs/sha256:block",
            app.base_url
        ))
        .body(axum::body::Body::empty())
        .expect("second registry request");

    let first_response = client.request(first_request).await.expect("first response");
    assert_eq!(first_response.status(), StatusCode::OK);

    let wait_start = tokio::time::Instant::now();
    while blob_hits.load(Ordering::SeqCst) != 1 {
        assert!(wait_start.elapsed() < Duration::from_secs(1));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let client_for_second = client.clone();
    let second_handle = tokio::spawn(async move {
        client_for_second
            .request(second_request)
            .await
            .expect("second response")
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(blob_hits.load(Ordering::SeqCst), 1);
    assert!(!second_handle.is_finished());

    release_first_blob.notify_waiters();
    let first_body = BodyExt::collect(first_response.into_body())
        .await
        .expect("read first blob body")
        .to_bytes();
    assert_eq!(first_body, Bytes::from_static(b"first"));

    let second_response = tokio::time::timeout(Duration::from_secs(1), second_handle)
        .await
        .expect("second request should proceed after first finishes")
        .expect("second join");
    let second_body = BodyExt::collect(second_response.into_body())
        .await
        .expect("read second blob body")
        .to_bytes();

    assert_eq!(second_body, Bytes::from_static(b"second"));
    assert_eq!(blob_hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_rate_limit_blocks_after_threshold() {
    common::setup();

    let mut settings = common::test_settings();
    settings.rate_limit.max_requests = 1;
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status1, _, _) = common::get(&format!("{}/api/stats", app.base_url)).await;
    let (status2, _, _) = common::get(&format!("{}/api/stats", app.base_url)).await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_proxy_follows_relative_redirects() {
    common::setup();

    let upstream = common::spawn_mock(
        Router::new()
            .route(
                "/download/v1/file.txt",
                get(|| async {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        "location",
                        HeaderValue::from_static("../artifact.txt?download=1"),
                    );
                    (StatusCode::FOUND, headers)
                }),
            )
            .route(
                "/download/artifact.txt",
                get(|| async {
                    let mut headers = HeaderMap::new();
                    headers.insert("content-type", HeaderValue::from_static("text/plain"));
                    headers.insert("content-length", HeaderValue::from_static("8"));
                    (StatusCode::OK, headers, "redirect")
                }),
            ),
    )
    .await;

    let app = common::spawn_app(common::build_state(common::test_settings())).await;
    let target = format!(
        "{}/{}/download/v1/file.txt",
        app.base_url, upstream.base_url
    );

    let (status, _, body) = common::get(&target).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "redirect");
}

#[tokio::test]
async fn test_proxy_rejects_redirect_to_disallowed_host() {
    common::setup();

    let upstream = common::spawn_mock(Router::new().route(
        "/redirect-out",
        get(|| async {
            let mut headers = HeaderMap::new();
            headers.insert(
                "location",
                HeaderValue::from_static("https://example.com/file.txt"),
            );
            (StatusCode::FOUND, headers)
        }),
    ))
    .await;

    let app = common::spawn_app(common::build_state(common::test_settings())).await;
    let target = format!("{}/{}/redirect-out", app.base_url, upstream.base_url);

    let (status, _, body) = common::get(&target).await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("Host Not Allowed"));
    assert!(body.contains("proxy.allowed_hosts"));
}

#[tokio::test]
async fn test_proxy_range_requests_bypass_cache_and_do_not_poison_l1() {
    common::setup();

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_route = Arc::clone(&hits);
    let upstream = common::spawn_mock(Router::new().route(
        "/range.bin",
        get(move |headers: HeaderMap| {
            let hits = Arc::clone(&hits_for_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);

                let mut response_headers = HeaderMap::new();
                response_headers.insert(
                    "cache-control",
                    HeaderValue::from_static("public, max-age=60"),
                );
                response_headers.insert(
                    "content-type",
                    HeaderValue::from_static("application/octet-stream"),
                );

                if headers.get(header::RANGE) == Some(&HeaderValue::from_static("bytes=0-3")) {
                    response_headers.insert(
                        header::CONTENT_RANGE,
                        HeaderValue::from_static("bytes 0-3/10"),
                    );
                    response_headers.insert("content-length", HeaderValue::from_static("4"));
                    (StatusCode::PARTIAL_CONTENT, response_headers, "0123").into_response()
                } else {
                    response_headers.insert("content-length", HeaderValue::from_static("10"));
                    (StatusCode::OK, response_headers, "0123456789").into_response()
                }
            }
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.cache.cacheable_patterns = vec!["*".to_string()];
    settings.cache.min_object_size = 1;
    let app = common::spawn_app(common::build_state(settings)).await;
    let target = format!("{}/{}/range.bin", app.base_url, upstream.base_url);

    let (range_status_1, range_headers_1, range_body_1) =
        common::request_with_headers(hyper::Method::GET, &target, &[("range", "bytes=0-3")]).await;
    let (full_status_1, full_headers_1, full_body_1) = common::get(&target).await;
    let (full_status_2, full_headers_2, full_body_2) = common::get(&target).await;
    let (range_status_2, range_headers_2, range_body_2) =
        common::request_with_headers(hyper::Method::GET, &target, &[("range", "bytes=0-3")]).await;

    assert_eq!(range_status_1, StatusCode::PARTIAL_CONTENT);
    assert_eq!(range_body_1, "0123");
    assert!(!range_headers_1.contains_key("x-cache"));

    assert_eq!(full_status_1, StatusCode::OK);
    assert_eq!(full_body_1, "0123456789");
    assert!(!full_headers_1.contains_key("x-cache"));

    assert_eq!(full_status_2, StatusCode::OK);
    assert_eq!(full_body_2, "0123456789");
    assert_eq!(
        full_headers_2
            .get("x-cache")
            .and_then(|value| value.to_str().ok()),
        Some("HIT from gh-proxy (L1)")
    );

    assert_eq!(range_status_2, StatusCode::PARTIAL_CONTENT);
    assert_eq!(range_body_2, "0123");
    assert!(!range_headers_2.contains_key("x-cache"));

    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn test_proxy_does_not_cache_set_cookie_responses() {
    common::setup();

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_route = Arc::clone(&hits);
    let upstream = common::spawn_mock(Router::new().route(
        "/cookie.txt",
        get(move || {
            let hits = Arc::clone(&hits_for_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let mut headers = HeaderMap::new();
                headers.insert(
                    "cache-control",
                    HeaderValue::from_static("public, max-age=60"),
                );
                headers.insert("content-type", HeaderValue::from_static("text/plain"));
                headers.insert("content-length", HeaderValue::from_static("6"));
                headers.insert(
                    header::SET_COOKIE,
                    HeaderValue::from_static("session=secret"),
                );
                (StatusCode::OK, headers, "cookie")
            }
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.cache.cacheable_patterns = vec!["*".to_string()];
    settings.cache.min_object_size = 1;
    let app = common::spawn_app(common::build_state(settings)).await;
    let target = format!("{}/{}/cookie.txt", app.base_url, upstream.base_url);

    let (status1, headers1, body1) = common::get(&target).await;
    let (status2, headers2, body2) = common::get(&target).await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(body1, "cookie");
    assert_eq!(body2, "cookie");
    assert!(!headers1.contains_key("x-cache"));
    assert!(!headers2.contains_key("x-cache"));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_proxy_does_not_cache_content_encoded_responses() {
    common::setup();

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_route = Arc::clone(&hits);
    let upstream = common::spawn_mock(Router::new().route(
        "/encoded.txt",
        get(move || {
            let hits = Arc::clone(&hits_for_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let mut headers = HeaderMap::new();
                headers.insert(
                    "cache-control",
                    HeaderValue::from_static("public, max-age=60"),
                );
                headers.insert("content-type", HeaderValue::from_static("text/plain"));
                headers.insert("content-length", HeaderValue::from_static("4"));
                headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                (StatusCode::OK, headers, "gzip")
            }
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    settings.cache.cacheable_patterns = vec!["*".to_string()];
    settings.cache.min_object_size = 1;
    let app = common::spawn_app(common::build_state(settings)).await;
    let target = format!("{}/{}/encoded.txt", app.base_url, upstream.base_url);

    let (status1, headers1, body1) = common::get(&target).await;
    let (status2, headers2, body2) = common::get(&target).await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(body1, "gzip");
    assert_eq!(body2, "gzip");
    assert!(!headers1.contains_key("x-cache"));
    assert!(!headers2.contains_key("x-cache"));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_github_route_rejects_non_file_path() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;

    let (status, _, body) = common::get(&format!("{}/github/owner/repo", app.base_url)).await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("repository-relative GitHub paths"));
    assert!(body.contains("/https://github.com/owner/repo/blob/main/file.txt"));
}

#[tokio::test]
async fn test_github_route_is_read_only() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;

    let (status, _, body) = common::request(
        hyper::Method::POST,
        &format!("{}/github/owner/repo/main/file.txt", app.base_url),
    )
    .await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(body.contains("Method Not Allowed"));
    assert!(body.contains("GET and HEAD"));
}

#[tokio::test]
async fn test_fallback_proxy_is_read_only() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;

    let (status, _, body) = common::request(
        hyper::Method::POST,
        &format!(
            "{}/https://github.com/owner/repo/blob/main/file.txt",
            app.base_url
        ),
    )
    .await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(body.contains("Method Not Allowed"));
    assert!(body.contains("GET and HEAD"));
}

#[tokio::test]
async fn test_ingress_host_guard_ignores_spoofed_x_forwarded_host() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "evil.example")
        .header("x-forwarded-host", "proxy.example.com")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(remote_addr));

    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("Origin Host Not Allowed"));
}

#[tokio::test]
async fn test_ingress_origin_auth_requires_configured_header_name() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    settings.ingress.auth_header_name = "x-custom-origin-auth".to_string();
    settings.ingress.auth_header_value = "secret".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut wrong_header_request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "proxy.example.com")
        .header("x-gh-proxy-origin-auth", "secret")
        .body(Body::empty())
        .expect("request");
    wrong_header_request
        .extensions_mut()
        .insert(ConnectInfo(remote_addr));

    let mut correct_header_request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "proxy.example.com")
        .header("x-custom-origin-auth", "secret")
        .body(Body::empty())
        .expect("request");
    correct_header_request
        .extensions_mut()
        .insert(ConnectInfo(remote_addr));

    let wrong_response = app
        .clone()
        .oneshot(wrong_header_request)
        .await
        .expect("wrong header response");
    let correct_response = app
        .oneshot(correct_header_request)
        .await
        .expect("correct header response");

    assert_eq!(wrong_response.status(), StatusCode::FORBIDDEN);
    assert_eq!(correct_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_registry_manifest_malformed_bearer_challenge_fails_closed() {
    common::setup();

    let upstream = common::spawn_mock(
        Router::new()
            .route(
                "/v2/",
                get(|| async { StatusCode::OK }).head(|| async { StatusCode::OK }),
            )
            .route(
                "/v2/library/test/manifests/latest",
                get(|| async {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::WWW_AUTHENTICATE,
                        HeaderValue::from_static("Bearer service=\"registry.test\""),
                    );
                    (StatusCode::UNAUTHORIZED, headers).into_response()
                }),
            ),
    )
    .await;

    let mut settings = common::test_settings();
    settings.registry.default = upstream.base_url.clone();
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status, _, body) = common::get(&format!(
        "{}/v2/library/test/manifests/latest",
        app.base_url
    ))
    .await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("401"));
}

#[tokio::test]
async fn test_registry_manifest_token_response_without_token_fails_closed() {
    common::setup();

    let token_service = common::spawn_mock(Router::new().route(
        "/token",
        get(|| async {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("application/json"));
            (StatusCode::OK, headers, r#"{"expires_in":60}"#)
        }),
    ))
    .await;

    let challenge = format!(
        "Bearer realm=\"{}/token\",service=\"registry.test\",scope=\"repository:library/test:pull\"",
        token_service.base_url
    );

    let upstream = common::spawn_mock(
        Router::new()
            .route(
                "/v2/",
                get(|| async { StatusCode::OK }).head(|| async { StatusCode::OK }),
            )
            .route(
                "/v2/library/test/manifests/latest",
                get(move || {
                    let challenge = challenge.clone();
                    async move {
                        let mut headers = HeaderMap::new();
                        headers.insert(
                            header::WWW_AUTHENTICATE,
                            HeaderValue::from_str(&challenge).expect("challenge header"),
                        );
                        (StatusCode::UNAUTHORIZED, headers).into_response()
                    }
                }),
            ),
    )
    .await;

    let mut settings = common::test_settings();
    settings.registry.default = upstream.base_url.clone();
    let app = common::spawn_app(common::build_state(settings)).await;

    let (status, _, body) = common::get(&format!(
        "{}/v2/library/test/manifests/latest",
        app.base_url
    ))
    .await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("401"));
}

#[tokio::test]
async fn test_registry_explicit_host_is_denied_when_not_allowlisted() {
    common::setup();

    let app = common::spawn_app(common::build_state(common::test_settings())).await;

    let (status, _, body) = common::get(&format!(
        "{}/v2/example.com/library/test/manifests/latest",
        app.base_url
    ))
    .await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("Registry Host Not Allowed"));
    assert!(body.contains("example.com"));
}
