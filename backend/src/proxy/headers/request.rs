use axum::http::HeaderMap;
use hyper::header;

pub fn sanitize_request_headers(
    headers: &mut HeaderMap,
    disable_compression: bool,
    ingress_auth_header_name: Option<&str>,
) {
    if disable_compression {
        headers.remove(header::ACCEPT_ENCODING);
    }

    headers.remove(header::HOST);
    headers.remove(header::CONNECTION);
    headers.remove(header::PROXY_AUTHENTICATE);
    headers.remove(header::PROXY_AUTHORIZATION);
    headers.remove(header::TE);
    headers.remove(header::TRAILER);
    headers.remove(header::UPGRADE);
    headers.remove("keep-alive");

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

#[cfg(test)]
mod tests {
    use super::sanitize_request_headers;
    use axum::http::{HeaderMap, HeaderValue};
    use hyper::header;

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
}
