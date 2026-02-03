//! HTTP client utilities.

use crate::config::ServerConfig;
use crate::state::HyperClient;
use axum::body::Body;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
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

/// Build the main hyper HTTP client for proxy operations.
pub fn build_client(_server: &ServerConfig) -> HyperClient {
    let mut http_connector = HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.enforce_http(false);
    http_connector.set_connect_timeout(Some(Duration::from_secs(10)));

    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http_connector);

    hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .http2_initial_stream_window_size(2 * 1024 * 1024)
        .http2_initial_connection_window_size(8 * 1024 * 1024)
        .http2_adaptive_window(true)
        .build(connector)
}

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
