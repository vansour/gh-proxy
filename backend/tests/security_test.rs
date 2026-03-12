//! Security and Ingress integration tests

mod common;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{StatusCode, header};
use gh_proxy::router;
use http_body_util::BodyExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tower::ServiceExt;

#[tokio::test]
async fn test_ingress_guard_rejects_mismatched_remote_host() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);
    
    // Simulate a remote client (non-loopback)
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
    assert!(body.contains("evil.example")); // Should echo the received host for debugging
}

#[tokio::test]
async fn test_ingress_guard_allows_loopback_regardless_of_host() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);
    
    // Simulate a loopback client
    let loopback_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

    let mut request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("host", "any-host.local")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(loopback_addr));

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_origin_auth_blocks_unauthorized_remote_requests() {
    common::setup();

    let mut settings = common::test_settings();
    settings.ingress.auth_header_value = "super-secret".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);
    
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    // Missing header
    let mut req1 = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .body(Body::empty())
        .expect("request");
    req1.extensions_mut().insert(ConnectInfo(remote_addr));

    // Wrong header value
    let mut req2 = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("x-gh-proxy-origin-auth", "wrong")
        .body(Body::empty())
        .expect("request");
    req2.extensions_mut().insert(ConnectInfo(remote_addr));

    let resp1 = app.clone().oneshot(req1).await.expect("response");
    let resp2 = app.oneshot(req2).await.expect("response");

    assert_eq!(resp1.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_origin_auth_allows_authorized_remote_requests() {
    common::setup();

    let mut settings = common::test_settings();
    settings.ingress.auth_header_value = "super-secret".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);
    
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);

    let mut request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/config")
        .header("x-gh-proxy-origin-auth", "super-secret")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(remote_addr));

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}
