use axum::body::Body;
use axum::http::{Response, StatusCode};
use tracing::warn;

pub(super) fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap_or_else(|err| {
            warn!(
                "Failed to build empty response with status {}: {}",
                status, err
            );
            Response::new(Body::empty())
        })
}
