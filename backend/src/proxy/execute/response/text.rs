use axum::body::Body;
use axum::http::{Response, Uri, header};
use futures_util::StreamExt;
use http_body_util::BodyExt;

use crate::errors::{ProxyError, ProxyResult};
use crate::middleware::{RequestLifecycle, RequestPermitGuard, mark_response_duration_recorded};
use crate::proxy::headers::{add_vary_header, fix_content_type_header, sanitize_response_headers};
use crate::proxy::stream::ProxyBodyStream;
use crate::services::text_processor::TextReplacementStream;
use crate::state::{AppState, ResponsePostProcessor};

#[allow(clippy::too_many_arguments)]
pub(super) fn text_processed_response(
    state: &AppState,
    mut parts: http::response::Parts,
    body: hyper::body::Incoming,
    final_uri: &Uri,
    processor: Option<ResponsePostProcessor>,
    lifecycle: RequestLifecycle,
    mut permit_guard: RequestPermitGuard,
    size_limit_bytes: u64,
    size_limit_mb: u64,
) -> ProxyResult<Response<Body>> {
    let proxy_url = super::processor_proxy_url(&processor).ok_or_else(|| {
        ProxyError::ProcessingError("response post-processor is missing proxy URL".to_string())
    })?;

    sanitize_response_headers(&mut parts.headers, true, true, true);
    fix_content_type_header(&mut parts.headers, final_uri);
    add_vary_header(&mut parts.headers);
    parts.headers.remove(header::CONTENT_LENGTH);

    let body_stream = body
        .into_data_stream()
        .map(|result| result.map_err(std::io::Error::other));
    let processed_stream = TextReplacementStream::new(body_stream, proxy_url);
    let wrapped_stream = processed_stream
        .map(|result| result.map_err(|error| ProxyError::ProcessingError(error.to_string())));

    let streaming_body = ProxyBodyStream::new(
        Box::pin(wrapped_stream),
        lifecycle,
        size_limit_bytes,
        size_limit_mb,
        permit_guard.take_start_time(),
        permit_guard.take_permit(),
        state.settings.shell.editor,
    );

    let mut response = Response::from_parts(parts, Body::from_stream(streaming_body));
    mark_response_duration_recorded(&mut response);
    Ok(response)
}
