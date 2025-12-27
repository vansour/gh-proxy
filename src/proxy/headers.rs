//! HTTP header manipulation for proxy requests and responses.
//!
//! Includes Cloudflare CDN cache optimization headers.

use axum::http::{HeaderMap, HeaderValue, Uri};
use hyper::header;

// ============================================================================
// Cache Control Constants for Cloudflare CDN
// ============================================================================

/// Static binary files (releases, archives) - long cache
const CACHE_STATIC_BINARY: &str = "public, max-age=86400, s-maxage=604800";

/// Release download files - medium cache (1 day browser, 7 days CDN)
#[allow(dead_code)]
const CACHE_RELEASE: &str = "public, max-age=86400, s-maxage=604800";

/// Raw content files - short cache (5 minutes browser, 1 hour CDN)
const CACHE_RAW_CONTENT: &str = "public, max-age=300, s-maxage=3600";

/// Dynamic content - very short cache
const CACHE_DYNAMIC: &str = "public, max-age=60, s-maxage=300";

// ============================================================================
// Request Header Sanitization
// ============================================================================

/// Sanitize request headers before forwarding.
pub fn sanitize_request_headers(headers: &mut HeaderMap, disable_compression: bool) {
    if disable_compression {
        headers.remove(header::ACCEPT_ENCODING);
    }

    // Remove hop-by-hop headers that shouldn't be forwarded
    headers.remove("connection");
    headers.remove("keep-alive");
    headers.remove("proxy-authenticate");
    headers.remove("proxy-authorization");
    headers.remove("te");
    headers.remove("trailers");
    headers.remove("upgrade");
}

// ============================================================================
// Response Header Sanitization
// ============================================================================

/// Sanitize response headers before returning to client.
pub fn sanitize_response_headers(
    headers: &mut HeaderMap,
    body_replaced: bool,
    strip_encoding: bool,
    loosen_security: bool,
) {
    if body_replaced {
        headers.remove(header::TRANSFER_ENCODING);
        headers.remove(header::CONTENT_LENGTH);
        headers.remove("connection");
        headers.remove("keep-alive");
    }
    if strip_encoding {
        headers.remove(header::CONTENT_ENCODING);
    }
    if loosen_security {
        headers.remove("content-security-policy");
        headers.remove("content-security-policy-report-only");
        headers.remove("x-frame-options");
        headers.remove("x-content-type-options");
    }
}

/// Fix Content-Type header if missing.
pub fn fix_content_type_header(headers: &mut HeaderMap, target_uri: &Uri) {
    if headers.contains_key(header::CONTENT_TYPE) {
        return;
    }
    let path = target_uri.path();
    let mime = if path.ends_with(".html") {
        "text/html"
    } else {
        "text/plain"
    };
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
}

// ============================================================================
// GitHub-Specific Headers
// ============================================================================

/// Apply GitHub-specific headers to request.
pub fn apply_github_headers(headers: &mut HeaderMap, _uri: &Uri, auth: Option<&HeaderValue>) {
    if let Some(a) = auth {
        headers.insert(header::AUTHORIZATION, a.clone());
    }
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static(concat!("gh-proxy/", env!("CARGO_PKG_VERSION"))),
    );
}

// ============================================================================
// Cloudflare CDN Cache Optimization
// ============================================================================

/// Determine if a path represents a static binary file (long cache).
fn is_static_binary(path: &str) -> bool {
    let static_extensions = [
        ".tar.gz",
        ".tgz",
        ".zip",
        ".exe",
        ".msi",
        ".dmg",
        ".pkg",
        ".deb",
        ".rpm",
        ".appimage",
        ".whl",
        ".jar",
        ".war",
        ".aar",
    ];
    static_extensions
        .iter()
        .any(|ext| path.to_lowercase().ends_with(ext))
}

/// Determine if a path represents a release download.
fn is_release_download(path: &str) -> bool {
    path.contains("/releases/download/")
}

/// Determine if a path represents raw content (source code, text files).
fn is_raw_content(path: &str) -> bool {
    path.contains("raw.githubusercontent.com") || path.contains("/raw/") || path.contains("/blob/")
}

/// Apply Cloudflare-optimized cache control headers to response.
///
/// This function sets appropriate Cache-Control and CDN-Cache-Control headers
/// based on the type of content being served, optimizing for Cloudflare's
/// edge caching behavior.
pub fn apply_cloudflare_cache_headers(headers: &mut HeaderMap, target_uri: &Uri) {
    let path = target_uri.path();

    // Determine appropriate cache policy based on content type
    let cache_control = if is_static_binary(path) || is_release_download(path) {
        CACHE_STATIC_BINARY
    } else if is_raw_content(path) {
        CACHE_RAW_CONTENT
    } else {
        CACHE_DYNAMIC
    };

    // Set standard Cache-Control
    if let Ok(value) = HeaderValue::from_str(cache_control) {
        headers.insert(header::CACHE_CONTROL, value);
    }

    // Set Cloudflare-specific CDN-Cache-Control for edge behavior
    // This takes precedence over Cache-Control for Cloudflare's edge
    if is_static_binary(path) || is_release_download(path) {
        let cdn_header: HeaderValue = HeaderValue::from_static("max-age=604800");
        headers.insert("CDN-Cache-Control", cdn_header);
    }
}

/// Forward relevant Cloudflare headers from upstream to client.
///
/// This helps with debugging and cache transparency.
#[allow(dead_code)]
pub fn forward_cloudflare_headers(response_headers: &mut HeaderMap, upstream_headers: &HeaderMap) {
    const CF_HEADERS: &[&str] = &["cf-cache-status", "cf-ray", "age"];

    for header_name in CF_HEADERS {
        if let Some(value) = upstream_headers.get(*header_name)
            && let Ok(name) = header::HeaderName::from_bytes(header_name.as_bytes())
        {
            response_headers.insert(name, value.clone());
        }
    }
}

/// Add Vary header for proper cache keying
pub fn add_vary_header(headers: &mut HeaderMap) {
    headers.insert(
        header::VARY,
        HeaderValue::from_static("Accept-Encoding, Accept"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_static_binary() {
        assert!(is_static_binary("/path/to/file.tar.gz"));
        assert!(is_static_binary("/path/to/file.zip"));
        assert!(is_static_binary("/path/to/file.exe"));
        assert!(!is_static_binary("/path/to/file.txt"));
        assert!(!is_static_binary("/path/to/file.sh"));
    }

    #[test]
    fn test_is_release_download() {
        assert!(is_release_download(
            "/owner/repo/releases/download/v1.0.0/file.tar.gz"
        ));
        assert!(!is_release_download("/owner/repo/raw/main/file.txt"));
    }

    #[test]
    fn test_is_raw_content() {
        assert!(is_raw_content(
            "https://raw.githubusercontent.com/owner/repo/main/file.txt"
        ));
        assert!(is_raw_content("/owner/repo/raw/main/file.txt"));
        assert!(!is_raw_content(
            "/owner/repo/releases/download/v1.0.0/file.tar.gz"
        ));
    }
}
