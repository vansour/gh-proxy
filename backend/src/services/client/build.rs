use crate::config::ServerConfig;
use crate::state::HyperClient;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

/// Build main hyper HTTP client for proxy operations.
pub fn build_client(server: &ServerConfig) -> HyperClient {
    let mut http_connector = HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.enforce_http(false);
    http_connector.set_connect_timeout(Some(Duration::from_secs(
        crate::utils::constants::http::CONNECT_TIMEOUT_SECS,
    )));

    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http_connector);

    hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(server.pool.idle_timeout_secs))
        .pool_max_idle_per_host(server.pool.max_idle_per_host)
        .http2_initial_stream_window_size(server.pool.http2_stream_window_size)
        .http2_initial_connection_window_size(server.pool.http2_connection_window_size)
        .http2_adaptive_window(true)
        .build(connector)
}
