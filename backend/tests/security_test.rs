//! Security and Ingress integration tests

mod common;

use axum::http::StatusCode;
use gh_proxy::router;

#[tokio::test]
async fn test_ingress_guard_rejects_mismatched_remote_host() {
    common::setup();

    let mut settings = common::test_settings();
    settings.shell.public_base_url = "https://proxy.example.com".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);

    let (status, _, body) = common::router_request(
        app,
        hyper::Method::GET,
        "/api/config",
        &[("host", "evil.example")],
        Some(common::remote_addr()),
    )
    .await;
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

    let (status, _, _) = common::router_request(
        app,
        hyper::Method::GET,
        "/api/config",
        &[("host", "any-host.local")],
        Some(common::loopback_addr()),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_origin_auth_blocks_unauthorized_remote_requests() {
    common::setup();

    let mut settings = common::test_settings();
    settings.ingress.auth_header_value = "super-secret".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);

    let (status1, _, _) = common::router_request(
        app.clone(),
        hyper::Method::GET,
        "/api/config",
        &[],
        Some(common::remote_addr()),
    )
    .await;
    let (status2, _, _) = common::router_request(
        app,
        hyper::Method::GET,
        "/api/config",
        &[("x-gh-proxy-origin-auth", "wrong")],
        Some(common::remote_addr()),
    )
    .await;

    assert_eq!(status1, StatusCode::FORBIDDEN);
    assert_eq!(status2, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_origin_auth_allows_authorized_remote_requests() {
    common::setup();

    let mut settings = common::test_settings();
    settings.ingress.auth_header_value = "super-secret".to_string();
    let state = common::build_state(settings);
    let app = router::create_router(state);

    let (status, _, _) = common::router_request(
        app,
        hyper::Method::GET,
        "/api/config",
        &[("x-gh-proxy-origin-auth", "super-secret")],
        Some(common::remote_addr()),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}
