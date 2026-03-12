//! Request metrics middleware.

use axum::{body::Body, http::Request, middleware::Next, response::Response};
use std::time::Instant;

use crate::infra;

#[derive(Debug, Clone, Copy, Default)]
struct DurationRecordedByHandler;

pub fn mark_response_duration_recorded(response: &mut Response) {
    response.extensions_mut().insert(DurationRecordedByHandler);
}

fn should_record_response_duration(response: &Response) -> bool {
    response
        .extensions()
        .get::<DurationRecordedByHandler>()
        .is_none()
}

/// Record request metrics for all routes.
///
/// Most routes only need the request/response lifecycle timing captured here.
/// Streaming proxy responses that observe end-to-end latency on body completion
/// mark the response so we can skip the shorter handler-only timing here.
pub async fn request_metrics_middleware(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let start = Instant::now();
    infra::metrics::record_method(method.as_str());
    infra::metrics::record_request_type(&path);

    let response = next.run(req).await;
    infra::metrics::HTTP_REQUESTS_TOTAL.inc();
    infra::metrics::record_status(response.status().as_u16());
    if should_record_response_duration(&response) {
        infra::metrics::HTTP_REQUEST_DURATION_SECONDS.observe(start.elapsed().as_secs_f64());
    }

    response
}

#[cfg(test)]
mod tests {
    use super::{mark_response_duration_recorded, should_record_response_duration};
    use axum::{body::Body, http::Response};

    #[test]
    fn responses_record_duration_by_default() {
        let response = Response::new(Body::empty());
        assert!(should_record_response_duration(&response));
    }

    #[test]
    fn marked_responses_skip_duration_tracking() {
        let mut response = Response::new(Body::empty());
        mark_response_duration_recorded(&mut response);

        assert!(!should_record_response_duration(&response));
    }
}
