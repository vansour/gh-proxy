/// HTTP client builder and configuration
/// Creates and configures the hyper HTTP client with TLS support
use axum::body::Body;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::config::ServerConfig;

/// Build a configured HTTP client with connection pooling and TLS
///
/// Configuration details:
/// - TCP_NODELAY: Enabled for reduced latency on small packets
/// - Connection timeout: Configurable via server.connectTimeoutSeconds
/// - Keep-alive: Configurable via server.keepAliveSeconds
/// - Pool: Configurable for efficient connection pooling per host
pub fn build_client(
    _server: &ServerConfig,
) -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
    let mut http_connector = HttpConnector::new();

    // Enable TCP_NODELAY to reduce latency for small packets
    http_connector.set_nodelay(true);

    // Configure connection timeout (0 disables explicit timeout)
    // Connection timeout and keep-alive are managed by defaults; removed from config

    // Enable both IPv4 and IPv6 with support for dual-stack
    http_connector.enforce_http(false);

    // Configure HTTPS connector with modern TLS settings
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http_connector);

    // Build client with optimized settings for connection pooling
    Client::builder(TokioExecutor::new())
        .http2_only(false) // Support both HTTP/1.1 and HTTP/2
        // Use default pool max idle per host
        .build(connector)
}
