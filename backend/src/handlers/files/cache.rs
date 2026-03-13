use super::paths::{LOCAL_WEB_ROOT_DISPLAY, read_web_bytes, read_web_string};
use bytes::Bytes;
use once_cell::sync::Lazy;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path as FsPath;

pub(super) const STATIC_CACHE_CONTROL: &str = "public, max-age=86400, immutable";
pub(super) const SHELL_CACHE_CONTROL: &str = "no-store";

pub(super) struct CachedFile {
    pub(super) content: Bytes,
    pub(super) etag: String,
    pub(super) content_type: &'static str,
    pub(super) cache_control: &'static str,
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

pub(super) static INDEX_HTML: Lazy<CachedFile> = Lazy::new(|| {
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

pub(super) static FAVICON: Lazy<CachedFile> = Lazy::new(|| {
    let content = read_web_bytes(FsPath::new("favicon.ico")).unwrap_or_default();
    CachedFile::new(content, "image/x-icon", STATIC_CACHE_CONTROL)
});
