use crate::utils;
use axum::{
    body::Body,
    extract::Path,
    http::{Response, StatusCode},
};
use bytes::Bytes;
use hyper::header;
use once_cell::sync::Lazy;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Component, Path as FsPath, PathBuf};
use tracing::error;

const CONTAINER_WEB_ROOT: &str = "/app/web";
const LOCAL_WEB_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frontend/dioxus-app/target/dx/gh-proxy-frontend/release/web/public"
);
const LOCAL_WEB_ROOT_DISPLAY: &str =
    "frontend/dioxus-app/target/dx/gh-proxy-frontend/release/web/public";
const STATIC_CACHE_CONTROL: &str = "public, max-age=86400, immutable";
const SHELL_CACHE_CONTROL: &str = "no-store";

struct CachedFile {
    content: Bytes,
    etag: String,
    content_type: &'static str,
    cache_control: &'static str,
}

impl CachedFile {
    fn new(content: Vec<u8>, content_type: &'static str, cache_control: &'static str) -> Self {
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        let etag = format!("\"{}\"", hasher.finish());

        Self {
            content: Bytes::from(content),
            etag,
            content_type,
            cache_control,
        }
    }

    fn from_string(
        content: String,
        content_type: &'static str,
        cache_control: &'static str,
    ) -> Self {
        Self::new(content.into_bytes(), content_type, cache_control)
    }
}

static INDEX_HTML: Lazy<CachedFile> = Lazy::new(|| {
    let html = read_web_string(FsPath::new("index.html")).unwrap_or_else(|| {
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GH-Proxy UI Unavailable</title>
</head>
<body>
    <main>
        <h1>GH-Proxy Web UI 未构建</h1>
        <p>请先运行 <code>dx build --release --debug-symbols false</code>。</p>
        <p>容器运行时产物应位于 <code>/app/web</code>，本地开发时可直接使用 <code>"#
            .to_string()
            + LOCAL_WEB_ROOT_DISPLAY
            + r#"</code>。</p>
    </main>
</body>
</html>"#
    });

    CachedFile::from_string(html, "text/html; charset=utf-8", SHELL_CACHE_CONTROL)
});

static FAVICON: Lazy<CachedFile> = Lazy::new(|| {
    let content = read_web_bytes(FsPath::new("favicon.ico")).unwrap_or_default();
    CachedFile::new(content, "image/x-icon", STATIC_CACHE_CONTROL)
});

fn is_safe_relative_path(path: &FsPath) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn resolve_web_file(relative_path: &FsPath) -> Option<PathBuf> {
    if !is_safe_relative_path(relative_path) {
        return None;
    }

    [CONTAINER_WEB_ROOT, LOCAL_WEB_ROOT]
        .iter()
        .map(|root| FsPath::new(root).join(relative_path))
        .find(|candidate| candidate.exists())
}

fn read_web_string(relative_path: &FsPath) -> Option<String> {
    resolve_web_file(relative_path).and_then(|path| fs::read_to_string(path).ok())
}

fn read_web_bytes(relative_path: &FsPath) -> Option<Vec<u8>> {
    resolve_web_file(relative_path).and_then(|path| fs::read(path).ok())
}

fn build_cached_response(cached: &CachedFile) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, cached.content_type)
        .header(header::ETAG, &cached.etag)
        .header(header::CACHE_CONTROL, cached.cache_control)
        .body(Body::from(cached.content.clone()))
        .unwrap_or_else(|err| {
            error!("Failed to build cached response: {}", err);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap_or_else(|_| Response::new(Body::from("Internal Server Error")))
        })
}

fn content_type_for_path(path: &str) -> &'static str {
    if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".map") {
        "application/json; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

pub async fn index() -> impl axum::response::IntoResponse {
    build_cached_response(&INDEX_HTML)
}

pub async fn serve_favicon() -> Response<Body> {
    if FAVICON.content.is_empty() {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "image/x-icon")
            .body(Body::empty())
            .unwrap_or_else(|err| {
                error!("Failed to build favicon response: {}", err);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()))
            })
    } else {
        build_cached_response(&FAVICON)
    }
}

pub async fn serve_static_asset(Path(path): Path<String>) -> Response<Body> {
    let relative_path = FsPath::new("assets").join(&path);
    let Some(asset_path) = resolve_web_file(&relative_path) else {
        return utils::errors::build_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "File not found".to_string(),
        );
    };
    let asset_path = asset_path.to_string_lossy().into_owned();
    let content = utils::errors::read_file_bytes_or_empty_async(&asset_path).await;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type_for_path(&path))
        .header(header::CACHE_CONTROL, STATIC_CACHE_CONTROL)
        .body(Body::from(content))
        .unwrap_or_else(|err| {
            error!("Failed to build static asset response: {}", err);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_relative_paths() {
        assert!(is_safe_relative_path(FsPath::new("assets/app.js")));
        assert!(!is_safe_relative_path(FsPath::new("/etc/passwd")));
        assert!(!is_safe_relative_path(FsPath::new("../secrets.txt")));
        assert!(!is_safe_relative_path(FsPath::new(
            "assets/../../secrets.txt"
        )));
    }
}
