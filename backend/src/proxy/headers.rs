//! HTTP header manipulation for proxy requests and responses.

use axum::http::{HeaderMap, HeaderValue, Uri};
use hyper::header;
use std::collections::BTreeSet;

// ============================================================================
// Request Header Sanitization
// ============================================================================

/// Sanitize request headers before forwarding.
pub fn sanitize_request_headers(
    headers: &mut HeaderMap,
    disable_compression: bool,
    ingress_auth_header_name: Option<&str>,
) {
    if disable_compression {
        headers.remove(header::ACCEPT_ENCODING);
    }

    // Remove Host so hyper can set the correct upstream host from the target URI.
    headers.remove(header::HOST);

    // Remove hop-by-hop headers that shouldn't be forwarded
    headers.remove(header::CONNECTION);
    headers.remove(header::PROXY_AUTHENTICATE);
    headers.remove(header::PROXY_AUTHORIZATION);
    headers.remove(header::TE);
    headers.remove(header::TRAILER);
    headers.remove(header::UPGRADE);

    // Remove keep-alive (not a standard constant in some hyper versions, but used in older HTTP)
    headers.remove("keep-alive");

    // Do not leak downstream proxy-chain metadata to upstream services.
    for name in [
        "cf-connecting-ip",
        "cf-ipcountry",
        "cf-ray",
        "cf-visitor",
        "cdn-loop",
        "cookie",
        "forwarded",
        "origin",
        "referer",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "true-client-ip",
        "via",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-real-ip",
    ] {
        headers.remove(name);
    }

    headers.remove("x-gh-proxy-origin-auth");
    if let Some(header_name) = ingress_auth_header_name
        && !header_name.eq_ignore_ascii_case("x-gh-proxy-origin-auth")
    {
        headers.remove(header_name);
    }
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
        headers.remove(header::CONNECTION);
        headers.remove("keep-alive");
    }
    if strip_encoding {
        headers.remove(header::CONTENT_ENCODING);
    }
    if loosen_security {
        headers.remove(header::CONTENT_SECURITY_POLICY);
        headers.remove(header::CONTENT_SECURITY_POLICY_REPORT_ONLY);
        headers.remove(header::X_FRAME_OPTIONS);
        headers.remove(header::X_CONTENT_TYPE_OPTIONS);
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
pub fn apply_github_headers(headers: &mut HeaderMap, uri: &Uri, auth: Option<&HeaderValue>) {
    headers.remove(header::AUTHORIZATION);

    if let Some(a) = auth
        && should_forward_github_auth(uri)
    {
        headers.insert(header::AUTHORIZATION, a.clone());
    }
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static(concat!("gh-proxy/", env!("CARGO_PKG_VERSION"))),
    );
}

fn should_forward_github_auth(uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };

    matches!(
        host,
        "github.com"
            | "api.github.com"
            | "raw.githubusercontent.com"
            | "codeload.github.com"
            | "gist.github.com"
    ) || host.ends_with(".github.com")
}

// ============================================================================
// Add Vary header for proper cache keying
// ============================================================================

/// Add Vary header for proper cache keying
pub fn add_vary_header(headers: &mut HeaderMap) {
    let Some(value) = merged_vary_header_value(headers.get(header::VARY)) else {
        return;
    };

    headers.insert(header::VARY, value);
}

fn merged_vary_header_value(existing: Option<&HeaderValue>) -> Option<HeaderValue> {
    if let Some(existing) = existing
        && let Ok(existing) = existing.to_str()
        && existing.split(',').map(str::trim).any(|token| token == "*")
    {
        return Some(HeaderValue::from_static("*"));
    }

    let mut tokens = BTreeSet::new();
    if let Some(existing) = existing
        && let Ok(existing) = existing.to_str()
    {
        for token in existing
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            tokens.insert(token.to_ascii_lowercase());
        }
    }

    tokens.insert("accept".to_string());

    let merged = tokens
        .into_iter()
        .map(|token| match token.as_str() {
            "accept" => "Accept".to_string(),
            _ => token,
        })
        .collect::<Vec<_>>()
        .join(", ");

    HeaderValue::from_str(&merged).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_request_headers_removes_host() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("proxy.local"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("198.51.100.10"),
        );
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.10, 203.0.113.7"),
        );
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.10"));
        headers.insert("forwarded", HeaderValue::from_static("for=198.51.100.10"));
        headers.insert("origin", HeaderValue::from_static("https://evil.example"));
        headers.insert(
            "referer",
            HeaderValue::from_static("https://evil.example/page"),
        );
        headers.insert("cookie", HeaderValue::from_static("session=secret"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));

        sanitize_request_headers(&mut headers, false, Some("x-gh-proxy-origin-auth"));

        assert!(!headers.contains_key(header::HOST));
        assert!(!headers.contains_key(header::CONNECTION));
        assert!(!headers.contains_key("cf-connecting-ip"));
        assert!(!headers.contains_key("x-forwarded-for"));
        assert!(!headers.contains_key("x-real-ip"));
        assert!(!headers.contains_key("forwarded"));
        assert!(!headers.contains_key("origin"));
        assert!(!headers.contains_key("referer"));
        assert!(!headers.contains_key("cookie"));
        assert!(!headers.contains_key("sec-fetch-site"));
    }

    #[test]
    fn sanitize_request_headers_removes_custom_origin_auth_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom-origin-auth", HeaderValue::from_static("secret"));

        sanitize_request_headers(&mut headers, false, Some("x-custom-origin-auth"));

        assert!(!headers.contains_key("x-custom-origin-auth"));
    }

    #[test]
    fn apply_github_headers_only_forwards_auth_to_safe_hosts() {
        let auth = HeaderValue::from_static("token secret");
        let mut github_headers = HeaderMap::new();
        apply_github_headers(
            &mut github_headers,
            &Uri::from_static("https://github.com/owner/repo/blob/main/file.txt"),
            Some(&auth),
        );
        assert_eq!(
            github_headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("token secret")
        );

        let mut asset_headers = HeaderMap::new();
        apply_github_headers(
            &mut asset_headers,
            &Uri::from_static(
                "https://objects.githubusercontent.com/github-production-release-asset",
            ),
            Some(&auth),
        );
        assert!(!asset_headers.contains_key(header::AUTHORIZATION));
    }

    #[test]
    fn add_vary_header_merges_existing_tokens_without_overwriting() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));

        add_vary_header(&mut headers);

        assert_eq!(
            headers
                .get(header::VARY)
                .and_then(|value| value.to_str().ok()),
            Some("Accept, origin")
        );
    }

    #[test]
    fn add_vary_header_preserves_vary_star() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("*"));

        add_vary_header(&mut headers);

        assert_eq!(
            headers
                .get(header::VARY)
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
    }
}
