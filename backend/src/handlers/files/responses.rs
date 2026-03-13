use super::cache::CachedFile;
use axum::{
    body::Body,
    http::{Response, StatusCode},
};
use hyper::header;
use tracing::error;

pub(super) fn build_cached_response(cached: &CachedFile) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, cached.content_type)
        .header(header::ETAG, &cached.etag)
        .header(header::CACHE_CONTROL, cached.cache_control)
        .body(Body::from(cached.content.clone()))
        .unwrap_or_else(|err| {
            error!("Failed to build cached response: {}", err);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap_or_else(|_| Response::new(Body::from("Internal Server Error")))
        })
}
