//! HTTP client utilities.

use crate::config::ServerConfig;
use crate::state::HyperClient;
use axum::body::Body;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::time::Duration;

/// Error type for HTTP operations.
#[derive(Debug)]
pub struct HttpError(pub String);

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HttpError {}

impl From<String> for HttpError {
    fn from(s: String) -> Self {
        HttpError(s)
    }
}

impl From<&str> for HttpError {
    fn from(s: &str) -> Self {
        HttpError(s.to_string())
    }
}

/// Build the main hyper HTTP client for proxy operations.
///
/// Optimized settings:
/// - Connection timeout to prevent hangs
/// - Balanced connection pool for GitHub/registry workloads
/// - HTTP/2 window sizes tuned for large file downloads
pub fn build_client(_server: &ServerConfig) -> HyperClient {
    let mut http_connector = HttpConnector::new();
    http_connector.set_nodelay(true); // Disable Nagle's algorithm for lower latency
    http_connector.enforce_http(false);
    http_connector.set_keepalive(Some(Duration::from_secs(90))); // Extended keepalive
    http_connector.set_connect_timeout(Some(Duration::from_secs(10))); // Connection timeout

    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http_connector);

    hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .http2_only(false)
        // Connection pool settings optimized for proxy workloads
        .pool_idle_timeout(Duration::from_secs(120)) // Longer idle for reuse
        .pool_max_idle_per_host(64) // Balanced pool size (was 128, too aggressive)
        // HTTP/2 window sizes for large file transfers
        .http2_initial_stream_window_size(2 * 1024 * 1024) // 2MB stream window
        .http2_initial_connection_window_size(8 * 1024 * 1024) // 8MB connection window
        .http2_adaptive_window(true) // Enable adaptive flow control
        .build(connector)
}

/// Send a GET request and deserialize JSON response.
pub async fn get_json<T: DeserializeOwned>(
    client: &HyperClient,
    url: &str,
    headers: Option<Vec<(&str, &str)>>,
    timeout_secs: u64,
) -> Result<T, HttpError> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|e| HttpError(format!("Invalid URL: {}", e)))?;

    let mut req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri);

    // Add headers
    if let Some(hdrs) = headers {
        for (k, v) in hdrs {
            req = req.header(k, v);
        }
    }

    let request = req
        .body(Body::empty())
        .map_err(|e| HttpError(format!("Failed to build request: {}", e)))?;

    // Execute with timeout
    let response = tokio::time::timeout(Duration::from_secs(timeout_secs), client.request(request))
        .await
        .map_err(|_| HttpError("Request timeout".to_string()))?
        .map_err(|e| HttpError(format!("Request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(HttpError(format!("HTTP error: {}", response.status())));
    }

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| HttpError(format!("Failed to read body: {}", e)))?
        .to_bytes();

    serde_json::from_slice(&body_bytes).map_err(|e| HttpError(format!("JSON parse error: {}", e)))
}

/// Send a POST request with JSON body and deserialize JSON response.
pub async fn post_json<T: DeserializeOwned, B: Serialize>(
    client: &HyperClient,
    url: &str,
    body: &B,
    headers: Option<Vec<(&str, &str)>>,
    timeout_secs: u64,
) -> Result<T, HttpError> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|e| HttpError(format!("Invalid URL: {}", e)))?;

    let json_body =
        serde_json::to_vec(body).map_err(|e| HttpError(format!("JSON serialize error: {}", e)))?;

    let mut req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(&uri)
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(hdrs) = headers {
        for (k, v) in hdrs {
            req = req.header(k, v);
        }
    }

    let request = req
        .body(Body::from(json_body))
        .map_err(|e| HttpError(format!("Failed to build request: {}", e)))?;

    let response = tokio::time::timeout(Duration::from_secs(timeout_secs), client.request(request))
        .await
        .map_err(|_| HttpError("Request timeout".to_string()))?
        .map_err(|e| HttpError(format!("Request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(HttpError(format!("HTTP error: {}", response.status())));
    }

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| HttpError(format!("Failed to read body: {}", e)))?
        .to_bytes();

    serde_json::from_slice(&body_bytes).map_err(|e| HttpError(format!("JSON parse error: {}", e)))
}

/// Send a GET request and return raw bytes.
pub async fn get_bytes(
    client: &HyperClient,
    url: &str,
    headers: Option<Vec<(&str, &str)>>,
    timeout_secs: u64,
) -> Result<(hyper::StatusCode, hyper::HeaderMap, Bytes), HttpError> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|e| HttpError(format!("Invalid URL: {}", e)))?;

    let mut req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri);

    if let Some(hdrs) = headers {
        for (k, v) in hdrs {
            req = req.header(k, v);
        }
    }

    let request = req
        .body(Body::empty())
        .map_err(|e| HttpError(format!("Failed to build request: {}", e)))?;

    let response = tokio::time::timeout(Duration::from_secs(timeout_secs), client.request(request))
        .await
        .map_err(|_| HttpError("Request timeout".to_string()))?
        .map_err(|e| HttpError(format!("Request failed: {}", e)))?;

    let status = response.status();
    let headers = response.headers().clone();

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| HttpError(format!("Failed to read body: {}", e)))?
        .to_bytes();

    Ok((status, headers, body_bytes))
}

/// Send a HEAD request and return status and headers.
pub async fn head_request(
    client: &HyperClient,
    url: &str,
    headers: Option<Vec<(&str, &str)>>,
    timeout_secs: u64,
) -> Result<(hyper::StatusCode, hyper::HeaderMap), HttpError> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|e| HttpError(format!("Invalid URL: {}", e)))?;

    let mut req = hyper::Request::builder()
        .method(hyper::Method::HEAD)
        .uri(&uri);

    if let Some(hdrs) = headers {
        for (k, v) in hdrs {
            req = req.header(k, v);
        }
    }

    let request = req
        .body(Body::empty())
        .map_err(|e| HttpError(format!("Failed to build request: {}", e)))?;

    let response = tokio::time::timeout(Duration::from_secs(timeout_secs), client.request(request))
        .await
        .map_err(|_| HttpError("Request timeout".to_string()))?
        .map_err(|e| HttpError(format!("Request failed: {}", e)))?;

    Ok((response.status(), response.headers().clone()))
}

/// Send a request and return the full response for streaming.
pub async fn request_streaming(
    client: &HyperClient,
    method: hyper::Method,
    url: &str,
    headers: Option<Vec<(String, String)>>,
    timeout_secs: u64,
) -> Result<hyper::Response<hyper::body::Incoming>, HttpError> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|e| HttpError(format!("Invalid URL: {}", e)))?;

    let mut req = hyper::Request::builder().method(method).uri(&uri);

    if let Some(hdrs) = headers {
        for (k, v) in hdrs {
            req = req.header(k.as_str(), v.as_str());
        }
    }

    let request = req
        .body(Body::empty())
        .map_err(|e| HttpError(format!("Failed to build request: {}", e)))?;

    tokio::time::timeout(Duration::from_secs(timeout_secs), client.request(request))
        .await
        .map_err(|_| HttpError("Request timeout".to_string()))?
        .map_err(|e| HttpError(format!("Request failed: {}", e)))
}
