/// Static file serving handlers
/// Handles serving of HTML, CSS, JavaScript, and favicon files
use axum::{
    body::Body,
    http::{Response, StatusCode, Uri},
};
use hyper::header;
use tracing::error;

use crate::utils;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};

/// GET / - Serve the main HTML page
pub async fn index() -> impl axum::response::IntoResponse {
    // Read index.html from disk on each request (no caching)
    let html = match fs::read_to_string("/app/web/index.html") {
        Ok(s) => s,
        Err(_) => r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>gh-proxy</title>
</head>
<body>
    <h1>gh-proxy - GitHub Proxy</h1>
    <p>Web UI not available. Please check the installation.</p>
</body>
</html>"#
            .to_string(),
    };

    // Compute ETag from content each time
    let mut hasher = DefaultHasher::new();
    html.hash(&mut hasher);
    let etag = format!("\"{}\"", hasher.finish());

    // Build response with headers
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::ETAG, etag)
        .body(Body::from(html))
        .unwrap_or_else(|e| {
            error!("Failed to build index response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap_or_else(|_| Response::new(Body::from("Internal Server Error")))
        })
}

/// GET /style.css - Serve static files
pub async fn serve_static_file(uri: Uri) -> Response<Body> {
    let path = uri.path().trim_start_matches('/');
    let file_path = format!("/app/web/{}", path);

    let content_type = match path {
        "style.css" => "text/css; charset=utf-8",
        "script.js" => "application/javascript; charset=utf-8",
        _ => "text/plain; charset=utf-8",
    };

    let content = utils::errors::read_file_bytes_or_empty(&file_path);

    if content.is_empty() && !std::path::Path::new(&file_path).exists() {
        utils::errors::build_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "File not found".to_string(),
        )
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(content))
            .unwrap_or_else(|e| {
                error!("Failed to build static file response: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()))
            })
    }
}

/// GET /favicon.ico - Serve favicon
pub async fn serve_favicon() -> Response<Body> {
    // Read favicon from disk on each request (no caching)
    let content = utils::errors::read_file_bytes_or_empty("/app/web/favicon.ico");

    if content.is_empty() {
        // Return a minimal 1x1 transparent ICO if file not found
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "image/x-icon")
            .body(Body::empty())
            .unwrap_or_else(|e| {
                error!("Failed to build favicon response: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()))
            })
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "image/x-icon")
            .header("ETag", "\"static-favicon\"")
            .body(Body::from(content.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to build favicon response: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()))
            })
    }
}
