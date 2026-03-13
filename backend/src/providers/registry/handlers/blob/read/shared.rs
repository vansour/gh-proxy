use crate::cache::response_cache::CachedResponse;
use crate::cache::utils::is_response_cacheable;
use crate::errors::ProxyError;
use crate::infra;
use crate::middleware::mark_response_duration_recorded;
use crate::proxy::headers::add_vary_header;
use crate::proxy::stream::ProxyBodyStream;
use crate::state::AppState;
use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use http_body_util::BodyExt;

pub(super) fn copy_upstream_headers(target: &mut Response, headers: &hyper::HeaderMap) {
    for (name, value) in headers {
        if let Ok(name) = header::HeaderName::try_from(name.as_str())
            && let Ok(value) = HeaderValue::try_from(value.as_bytes())
        {
            target.headers_mut().insert(name, value);
        }
    }
}

pub(super) fn response_metadata(response: &Response) -> (Option<u64>, String) {
    let content_length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    (content_length, content_type)
}

pub(super) fn apply_cache_headers(
    state: &AppState,
    response: &mut Response,
    cache_key: &crate::cache::key::CacheKey,
    request_path: &str,
    status: StatusCode,
    content_type: &str,
) -> bool {
    let response_cacheable = state
        .cache_manager
        .should_cache_request(cache_key, request_path)
        && is_response_cacheable(
            status.as_u16(),
            response.headers(),
            state.cache_manager.config(),
        );
    for (name, value) in
        state
            .cache_manager
            .build_cache_headers(content_type, status, response_cacheable)
    {
        response.headers_mut().insert(name, value);
    }
    add_vary_header(response.headers_mut());
    response_cacheable
}

pub(super) fn should_buffer_for_cache(
    state: &AppState,
    response_cacheable: bool,
    content_length: Option<u64>,
) -> bool {
    response_cacheable
        && content_length
            .map(|len| {
                let cache_config = state.cache_manager.config();
                len >= cache_config.min_object_size && len <= cache_config.max_object_size
            })
            .unwrap_or(false)
}

pub(super) async fn buffered_blob_response(
    state: &AppState,
    mut response: Response,
    hyper_resp: hyper::Response<hyper::body::Incoming>,
    status: StatusCode,
    cache_key: crate::cache::key::CacheKey,
    mut lifecycle: crate::middleware::RequestLifecycle,
    permit_guard: crate::middleware::RequestPermitGuard,
) -> Response {
    let body_bytes = match BodyExt::collect(http_body_util::Limited::new(
        Body::from_stream(
            hyper_resp
                .into_body()
                .into_data_stream()
                .map(|result| result.map_err(std::io::Error::other)),
        ),
        (state.cache_manager.config().max_object_size + 1) as usize,
    ))
    .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            tracing::error!("Failed to buffer registry blob for cache: {}", error);
            return (
                StatusCode::BAD_GATEWAY,
                format!("Error: failed to read blob response: {}", error),
            )
                .into_response();
        }
    };

    if let Some(cached) = CachedResponse::from_buffered_parts(
        status,
        response.headers().clone(),
        body_bytes.clone(),
        state.cache_manager.config(),
        cache_key,
        state.cache_manager.metrics(),
    ) {
        *response.headers_mut() = cached.headers.clone();
        state.cache_manager.set(cached.key.clone(), cached).await;
    }

    infra::metrics::BYTES_TRANSFERRED_TOTAL.inc_by(body_bytes.len() as u64);
    lifecycle.success();
    drop(permit_guard);
    *response.body_mut() = Body::from(body_bytes);
    response
}

pub(super) fn streaming_blob_response(
    mut response: Response,
    hyper_resp: hyper::Response<hyper::body::Incoming>,
    lifecycle: crate::middleware::RequestLifecycle,
    mut permit_guard: crate::middleware::RequestPermitGuard,
) -> Response {
    let streaming_body = ProxyBodyStream::new(
        hyper_resp
            .into_body()
            .into_data_stream()
            .map(|result| result.map_err(|error| ProxyError::Http(Box::new(error))))
            .boxed(),
        lifecycle,
        0,
        0,
        permit_guard.take_start_time(),
        permit_guard.take_permit(),
        false,
    );
    *response.body_mut() = Body::from_stream(streaming_body);
    mark_response_duration_recorded(&mut response);
    response
}
