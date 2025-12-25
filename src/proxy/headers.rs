//! HTTP header manipulation for proxy requests and responses.

use axum::http::{HeaderMap, HeaderValue, Uri};
use hyper::header;

/// Sanitize request headers before forwarding.
pub fn sanitize_request_headers(headers: &mut HeaderMap, disable_compression: bool) {
    if disable_compression {
        headers.remove(header::ACCEPT_ENCODING);
    }
}

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
