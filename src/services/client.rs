use crate::config::ServerConfig;
use axum::body::Body;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

pub fn build_client(
    _server: &ServerConfig,
) -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
    let mut http_connector = HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.enforce_http(false);

    // 优化：增加 TCP Keepalive 探测，防止连接在静默期间被防火墙切断
    http_connector.set_keepalive(Some(Duration::from_secs(60)));

    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http_connector);

    Client::builder(TokioExecutor::new())
        .http2_only(false)
        // Cloudflare 场景优化：
        // 1. 增加空闲连接超时时间 (GitHub 支持较长的 keep-alive)
        .pool_idle_timeout(Duration::from_secs(90))
        // 2. 针对特定主机的最大空闲连接数。
        // 因为我们主要访问 github.com，这里设置大一点可以复用更多连接。
        .pool_max_idle_per_host(128)
        // 3. HTTP/2 窗口大小优化，加速大文件传输
        .http2_initial_stream_window_size(1024 * 1024) // 1MB 初始流窗口
        .http2_initial_connection_window_size(4 * 1024 * 1024) // 4MB 初始连接窗口
        .build(connector)
}
