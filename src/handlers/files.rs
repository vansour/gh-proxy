use crate::utils;
use axum::{
    body::Body,
    http::{Response, StatusCode, Uri},
};
use bytes::Bytes;
use hyper::header;
use once_cell::sync::Lazy;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use tracing::error;

/// Static file cache headers for Cloudflare CDN optimization
const STATIC_CACHE_CONTROL: &str = "public, max-age=86400, immutable";

/// Cached static file with computed ETag
struct CachedFile {
    content: Bytes,
    etag: String,
    content_type: &'static str,
}

impl CachedFile {
    fn new(content: Vec<u8>, content_type: &'static str) -> Self {
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        let etag = format!("\"{}\"", hasher.finish());
        Self {
            content: Bytes::from(content),
            etag,
            content_type,
        }
    }

    fn from_string(content: String, content_type: &'static str) -> Self {
        Self::new(content.into_bytes(), content_type)
    }
}

/// Pre-loaded index.html
static INDEX_HTML: Lazy<CachedFile> = Lazy::new(|| {
    let html = fs::read_to_string("/app/web/index.html").unwrap_or_else(|_| {
        r#"<!DOCTYPE html>
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
            .to_string()
    });
    CachedFile::from_string(html, "text/html; charset=utf-8")
});

/// Pre-loaded style.css
static STYLE_CSS: Lazy<CachedFile> = Lazy::new(|| {
    let content = fs::read("/app/web/style.css").unwrap_or_default();
    CachedFile::new(content, "text/css; charset=utf-8")
});

/// Pre-loaded script.js
static SCRIPT_JS: Lazy<CachedFile> = Lazy::new(|| {
    let content = fs::read("/app/web/script.js").unwrap_or_default();
    CachedFile::new(content, "application/javascript; charset=utf-8")
});

/// Pre-loaded favicon.ico
static FAVICON: Lazy<CachedFile> = Lazy::new(|| {
    let content = fs::read("/app/web/favicon.ico").unwrap_or_default();
    CachedFile::new(content, "image/x-icon")
});

/// Pre-loaded docker/index.html
static DOCKER_INDEX: Lazy<CachedFile> = Lazy::new(|| {
    let html = fs::read_to_string("/app/web/docker/index.html")
        .unwrap_or_else(|_| "<html><body><h1>Docker UI missing</h1></body></html>".to_string());
    CachedFile::from_string(html, "text/html; charset=utf-8")
});

/// Build a cached response with proper headers for CDN
fn build_cached_response(cached: &CachedFile) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, cached.content_type)
        .header(header::ETAG, &cached.etag)
        .header(header::CACHE_CONTROL, STATIC_CACHE_CONTROL)
        .body(Body::from(cached.content.clone()))
        .unwrap_or_else(|e| {
            error!("Failed to build cached response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap_or_else(|_| Response::new(Body::from("Internal Server Error")))
        })
}

pub async fn index() -> impl axum::response::IntoResponse {
    build_cached_response(&INDEX_HTML)
}

pub async fn serve_static_file(uri: Uri) -> Response<Body> {
    let path = uri.path().trim_start_matches('/');

    // Use pre-cached files for known static assets
    match path {
        "style.css" => {
            if STYLE_CSS.content.is_empty() {
                return utils::errors::build_response(
                    StatusCode::NOT_FOUND,
                    "text/plain; charset=utf-8",
                    "File not found".to_string(),
                );
            }
            build_cached_response(&STYLE_CSS)
        }
        "script.js" => {
            if SCRIPT_JS.content.is_empty() {
                return utils::errors::build_response(
                    StatusCode::NOT_FOUND,
                    "text/plain; charset=utf-8",
                    "File not found".to_string(),
                );
            }
            build_cached_response(&SCRIPT_JS)
        }
        _ => {
            // Fallback for unknown files - read from disk
            let file_path = format!("/app/web/{}", path);
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
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .header(header::CACHE_CONTROL, STATIC_CACHE_CONTROL)
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
    }
}

pub async fn serve_favicon() -> Response<Body> {
    if FAVICON.content.is_empty() {
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
        build_cached_response(&FAVICON)
    }
}

pub async fn serve_docker_index() -> impl axum::response::IntoResponse {
    build_cached_response(&DOCKER_INDEX)
}
