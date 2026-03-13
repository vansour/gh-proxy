use axum::body::Body;
use axum::http::{Response, StatusCode};
use futures_util::StreamExt;
use http_body_util::BodyExt;

use crate::cache::key::CacheKey;
use crate::cache::response_cache::CachedResponse;
use crate::errors::{ProxyError, ProxyResult};
use crate::infra;
use crate::middleware::{RequestLifecycle, RequestPermitGuard};
use crate::state::AppState;

#[allow(clippy::too_many_arguments)]
pub(super) async fn buffered_response(
    state: &AppState,
    mut parts: http::response::Parts,
    body: hyper::body::Incoming,
    status: StatusCode,
    cache_key: CacheKey,
    mut lifecycle: RequestLifecycle,
    permit_guard: RequestPermitGuard,
    size_limit_bytes: u64,
    size_limit_mb: u64,
) -> ProxyResult<Response<Body>> {
    let cache_config = state.cache_manager.config();
    let body_bytes = BodyExt::collect(http_body_util::Limited::new(
        Body::from_stream(
            body.into_data_stream()
                .map(|result| result.map_err(std::io::Error::other)),
        ),
        (cache_config.max_object_size + 1) as usize,
    ))
    .await
    .map_err(|error| ProxyError::ProcessingError(error.to_string()))?
    .to_bytes();

    if body_bytes.len() as u64 > size_limit_bytes {
        let error = super::size_limit_error(body_bytes.len() as u64, size_limit_mb);
        lifecycle.fail(Some(&error));
        return Err(error);
    }

    if let Some(cached) = CachedResponse::from_buffered_parts(
        status,
        parts.headers.clone(),
        body_bytes.clone(),
        cache_config,
        cache_key.clone(),
        state.cache_manager.metrics(),
    ) {
        parts.headers = cached.headers.clone();
        state.cache_manager.set(cache_key, cached).await;
    }

    infra::metrics::BYTES_TRANSFERRED_TOTAL.inc_by(body_bytes.len() as u64);
    lifecycle.success();
    drop(permit_guard);

    Ok(Response::from_parts(parts, Body::from(body_bytes)))
}
