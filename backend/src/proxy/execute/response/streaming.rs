use axum::body::Body;
use axum::http::Response;
use futures_util::StreamExt;
use http_body_util::BodyExt;

use crate::errors::ProxyError;
use crate::middleware::{RequestLifecycle, RequestPermitGuard, mark_response_duration_recorded};
use crate::proxy::stream::ProxyBodyStream;

pub(super) fn streaming_response(
    parts: http::response::Parts,
    body: hyper::body::Incoming,
    lifecycle: RequestLifecycle,
    mut permit_guard: RequestPermitGuard,
    size_limit_bytes: u64,
    size_limit_mb: u64,
    shell_editor_enabled: bool,
) -> Response<Body> {
    let streaming_body = ProxyBodyStream::new(
        body.into_data_stream()
            .map(|result| result.map_err(|error| ProxyError::Http(Box::new(error))))
            .boxed(),
        lifecycle,
        size_limit_bytes,
        size_limit_mb,
        permit_guard.take_start_time(),
        permit_guard.take_permit(),
        shell_editor_enabled,
    );

    let mut response = Response::from_parts(parts, Body::from_stream(streaming_body));
    mark_response_duration_recorded(&mut response);
    response
}
