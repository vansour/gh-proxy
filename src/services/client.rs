use crate::config::ServerConfig;
use axum::body::Body;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
pub fn build_client(
    _server: &ServerConfig,
) -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
    let mut http_connector = HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.enforce_http(false);
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http_connector);
    Client::builder(TokioExecutor::new())
        .http2_only(false)
        .build(connector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_client() {
        let config = ServerConfig::default();
        let _client = build_client(&config);
        // Just verify it builds without panicking
    }

    #[test]
    fn test_build_client_with_custom_config() {
        let config = ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 9000,
            size_limit: 200,
            request_timeout_secs: 60,
            max_concurrent_requests: 10,
            permit_acquire_timeout_secs: 5,
        };
        let _client = build_client(&config);
        // Just verify it builds without panicking
    }
}
