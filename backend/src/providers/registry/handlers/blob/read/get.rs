use super::shared::{
    apply_cache_headers, buffered_blob_response, copy_upstream_headers, response_metadata,
    should_buffer_for_cache, streaming_blob_response,
};
use crate::cache::manager::CacheReservation;
use crate::providers::registry::handlers::common::{
    begin_registry_request, blob_cache_key, cache_hit_response, registry_host_not_allowed_response,
};
use crate::state::AppState;
use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

pub(in crate::providers::registry::handlers) async fn get_blob(
    State(state): State<AppState>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let proxy = Arc::clone(&state.docker_proxy);
    let request_path = format!("/v2/{}/blobs/{}", name, digest);
    let cache_key = match blob_cache_key(&proxy, &name, &digest) {
        Ok(cache_key) => cache_key,
        Err(error) => return registry_host_not_allowed_response(error),
    };

    let cache_fill_guard = match state.cache_manager.get_or_reserve_fill(&cache_key).await {
        CacheReservation::Hit(cached) => return cache_hit_response(*cached, false),
        CacheReservation::Fill(guard) => guard,
    };

    let (lifecycle, permit_guard) = match begin_registry_request(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    match proxy.get_blob(&name, &digest).await {
        Ok(hyper_resp) => {
            let status = hyper_resp.status();
            let mut response = Response::new(Body::empty());
            *response.status_mut() = status;
            copy_upstream_headers(&mut response, hyper_resp.headers());

            let (content_length, content_type) = response_metadata(&response);
            let response_cacheable = apply_cache_headers(
                &state,
                &mut response,
                &cache_key,
                &request_path,
                status,
                &content_type,
            );

            if should_buffer_for_cache(&state, response_cacheable, content_length) {
                return buffered_blob_response(
                    &state,
                    response,
                    hyper_resp,
                    status,
                    cache_key,
                    lifecycle,
                    permit_guard,
                )
                .await;
            }

            drop(cache_fill_guard);
            streaming_blob_response(response, hyper_resp, lifecycle, permit_guard)
        }
        Err(error) => {
            drop(cache_fill_guard);
            tracing::error!("Error getting blob: {}", error);
            (StatusCode::BAD_GATEWAY, format!("Error: {}", error)).into_response()
        }
    }
}
