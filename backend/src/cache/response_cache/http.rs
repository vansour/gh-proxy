use super::CachedResponse;
use axum::body::Body;
use tracing::warn;

impl CachedResponse {
    pub fn to_response(&self) -> axum::http::Response<Body> {
        let mut response = axum::http::Response::builder()
            .status(self.status)
            .body(Body::from(self.body.clone()))
            .unwrap_or_else(|err| {
                warn!("Failed to build cached response body: {}", err);
                axum::http::Response::new(Body::from(self.body.clone()))
            });

        for (name, value) in &self.headers {
            let name_str = name.as_str();
            if matches!(
                name_str,
                "connection"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "upgrade"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailers"
            ) {
                continue;
            }

            if name_str == "age" {
                let age = self.cached_at.elapsed().as_secs().to_string();
                if let Ok(age_value) = age.parse() {
                    response.headers_mut().insert(name, age_value);
                }
                continue;
            }

            response.headers_mut().insert(name, value.clone());
        }

        let age = self.cached_at.elapsed().as_secs().to_string();
        if let Ok(age_value) = age.parse() {
            response.headers_mut().insert("age", age_value);
        }

        if let Ok(value) = "HIT from gh-proxy (L1)".parse() {
            response.headers_mut().insert("X-Cache", value);
        }

        response
    }
}
