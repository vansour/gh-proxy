use super::HttpError;
use crate::state::HyperClient;
use axum::body::Body;
use bytes::Bytes;
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;
use std::time::Duration;

pub async fn get_json<T: DeserializeOwned>(
    client: &HyperClient,
    url: &str,
    headers: Option<Vec<(&str, &str)>>,
    timeout_secs: u64,
) -> Result<T, HttpError> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|error| HttpError(format!("Invalid URL: {}", error)))?;

    let mut req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri);

    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            req = req.header(key, value);
        }
    }

    let request = req
        .body(Body::empty())
        .map_err(|error| HttpError(format!("Failed to build request: {}", error)))?;

    let response = tokio::time::timeout(Duration::from_secs(timeout_secs), client.request(request))
        .await
        .map_err(|_| HttpError("Request timeout".to_string()))?
        .map_err(|error| HttpError(format!("Request failed: {}", error)))?;

    if !response.status().is_success() {
        return Err(HttpError(format!("HTTP error: {}", response.status())));
    }

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|error| HttpError(format!("Failed to read body: {}", error)))?
        .to_bytes();

    serde_json::from_slice(&body_bytes)
        .map_err(|error| HttpError(format!("JSON parse error: {}", error)))
}

pub async fn get_bytes(
    client: &HyperClient,
    url: &str,
    headers: Option<Vec<(&str, &str)>>,
    timeout_secs: u64,
) -> Result<(hyper::StatusCode, hyper::HeaderMap, Bytes), HttpError> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|error| HttpError(format!("Invalid URL: {}", error)))?;

    let mut req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri);

    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            req = req.header(key, value);
        }
    }

    let request = req
        .body(Body::empty())
        .map_err(|error| HttpError(format!("Failed to build request: {}", error)))?;

    let response = tokio::time::timeout(Duration::from_secs(timeout_secs), client.request(request))
        .await
        .map_err(|_| HttpError("Request timeout".to_string()))?
        .map_err(|error| HttpError(format!("Request failed: {}", error)))?;

    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|error| HttpError(format!("Failed to read body: {}", error)))?
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
        .map_err(|error| HttpError(format!("Invalid URL: {}", error)))?;

    let mut req = hyper::Request::builder()
        .method(hyper::Method::HEAD)
        .uri(&uri);

    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            req = req.header(key, value);
        }
    }

    let request = req
        .body(Body::empty())
        .map_err(|error| HttpError(format!("Failed to build request: {}", error)))?;

    let response = tokio::time::timeout(Duration::from_secs(timeout_secs), client.request(request))
        .await
        .map_err(|_| HttpError("Request timeout".to_string()))?
        .map_err(|error| HttpError(format!("Request failed: {}", error)))?;

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
        .map_err(|error| HttpError(format!("Invalid URL: {}", error)))?;

    let mut req = hyper::Request::builder().method(method).uri(&uri);

    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            req = req.header(key.as_str(), value.as_str());
        }
    }

    let request = req
        .body(Body::empty())
        .map_err(|error| HttpError(format!("Failed to build request: {}", error)))?;

    tokio::time::timeout(Duration::from_secs(timeout_secs), client.request(request))
        .await
        .map_err(|_| HttpError("Request timeout".to_string()))?
        .map_err(|error| HttpError(format!("Request failed: {}", error)))
}
