use axum::{
    body::Body, http::Request, http::header::HeaderValue, middleware::Next, response::Response,
};
use hyper::header;

const NO_STORE_CACHE_CONTROL: &str = "no-store, no-cache, max-age=0";
const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

pub async fn response_hardening_middleware(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("no-referrer"));
    headers
        .entry(header::HeaderName::from_static("permissions-policy"))
        .or_insert(HeaderValue::from_static(PERMISSIONS_POLICY));

    if should_harden_same_origin_surface(&path) {
        headers
            .entry(header::X_FRAME_OPTIONS)
            .or_insert(HeaderValue::from_static("DENY"));
    }

    if should_disable_caching(&path) {
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static(NO_STORE_CACHE_CONTROL));
        headers
            .entry(header::PRAGMA)
            .or_insert(HeaderValue::from_static("no-cache"));
        headers
            .entry(header::EXPIRES)
            .or_insert(HeaderValue::from_static("0"));
    }

    response
}

fn should_harden_same_origin_surface(path: &str) -> bool {
    matches!(
        path,
        "/" | "/status" | "/healthz" | "/readyz" | "/metrics" | "/registry/healthz"
    ) || path.starts_with("/api/")
        || path.starts_with("/debug/")
        || path.starts_with("/assets/")
}

fn should_disable_caching(path: &str) -> bool {
    matches!(
        path,
        "/healthz" | "/readyz" | "/metrics" | "/registry/healthz"
    ) || path.starts_with("/api/")
        || path.starts_with("/debug/")
}

#[cfg(test)]
mod tests {
    use super::{should_disable_caching, should_harden_same_origin_surface};

    #[test]
    fn hardens_same_origin_ui_and_api_paths() {
        assert!(should_harden_same_origin_surface("/"));
        assert!(should_harden_same_origin_surface("/api/config"));
        assert!(should_harden_same_origin_surface("/assets/app.js"));
        assert!(!should_harden_same_origin_surface(
            "/https://github.com/openai/gpt"
        ));
        assert!(!should_harden_same_origin_surface(
            "/github/openai/gpt/main/README.md"
        ));
    }

    #[test]
    fn only_disables_caching_for_dynamic_operational_paths() {
        assert!(should_disable_caching("/api/stats"));
        assert!(should_disable_caching("/healthz"));
        assert!(should_disable_caching("/metrics"));
        assert!(!should_disable_caching("/"));
        assert!(!should_disable_caching("/assets/app.js"));
        assert!(!should_disable_caching("/https://github.com/openai/gpt"));
    }
}
