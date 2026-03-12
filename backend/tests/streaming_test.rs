//! Streaming and backpressure integration tests

mod common;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::routing::get;
use bytes::Bytes;
use gh_proxy::router;
use http_body_util::BodyExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

#[tokio::test]
async fn test_large_file_streaming_chunking() {
    common::setup();

    let chunk_count = Arc::new(AtomicUsize::new(0));
    let chunk_count_inner = Arc::clone(&chunk_count);

    // Create a 1MB body
    let large_data = vec![0u8; 1024 * 1024];
    let large_data_bytes = Bytes::from(large_data.clone());

    let upstream = common::spawn_mock(Router::new().route(
        "/large.bin",
        get(move || {
            let data = large_data_bytes.clone();
            async move { (StatusCode::OK, data) }
        }),
    ))
    .await;

    let mut settings = common::test_settings();
    // Enable proxy for the mock upstream
    settings.proxy.allowed_hosts.push("127.0.0.1".to_string());
    let state = common::build_state(settings);
    let app = router::create_router(state);

    let mut request = axum::http::Request::builder()
        .method(hyper::Method::GET)
        .uri(format!("/{}/large.bin", upstream.base_url))
        .body(Body::empty())
        .expect("request");

    // Crucial: insert ConnectInfo for middlewares
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))));

    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    if status != StatusCode::OK {
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        panic!(
            "Request failed with status {}: {}",
            status,
            String::from_utf8_lossy(&body_bytes)
        );
    }

    let mut body = response.into_body();
    let mut total_received = 0;

    // We expect the body to be chunked into 256KB pieces
    // 1MB / 256KB = 4 chunks
    while let Some(chunk) = body.frame().await {
        let frame = chunk.expect("frame");
        if let Some(data) = frame.data_ref() {
            total_received += data.len();
            chunk_count_inner.fetch_add(1, Ordering::SeqCst);

            // Each chunk should be at most 256KB (UNIFIED_BUFFER_SIZE)
            assert!(
                data.len() <= 256 * 1024,
                "Chunk size {} exceeds 256KB",
                data.len()
            );
        }
    }

    assert_eq!(total_received, 1024 * 1024);
    // Note: Depending on how hyper/axum handles the initial body,
    // it might be exactly 4 chunks if our ProxyBodyStream is doing its job.
    let final_chunks = chunk_count.load(Ordering::SeqCst);
    assert!(
        final_chunks >= 4,
        "Expected at least 4 chunks for 1MB data, got {}",
        final_chunks
    );
}
