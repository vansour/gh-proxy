use axum::http::{HeaderMap, HeaderValue, Uri};
use hyper::header;

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

pub fn fix_content_type_header(headers: &mut HeaderMap, target_uri: &Uri) {
    if headers.contains_key(header::CONTENT_TYPE) {
        return;
    }

    let mime = if target_uri.path().ends_with(".html") {
        "text/html"
    } else {
        "text/plain"
    };
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
}
