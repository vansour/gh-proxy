use crate::cache::response_cache::CacheResult;
use crate::providers::registry::handlers::common::{
    begin_registry_request, blob_cache_key, cache_hit_response, registry_host_not_allowed_response,
};
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

pub(in crate::providers::registry::handlers) async fn head_blob(
    State(state): State<AppState>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let proxy = Arc::clone(&state.docker_proxy);
    let cache_key = match blob_cache_key(&proxy, &name, &digest) {
        Ok(cache_key) => cache_key,
        Err(error) => return registry_host_not_allowed_response(error),
    };

    match state.cache_manager.get(&cache_key).await {
        CacheResult::Hit(cached) => return cache_hit_response(*cached, true),
        CacheResult::Miss => {}
    }

    let (mut lifecycle, permit_guard) = match begin_registry_request(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    match proxy.head_blob(&name, &digest).await {
        Ok(size) => {
            let mut headers = HeaderMap::new();
            if let Ok(cl_value) = size.to_string().parse() {
                headers.insert(header::CONTENT_LENGTH, cl_value);
            }
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            lifecycle.success();
            drop(permit_guard);
            (StatusCode::OK, headers).into_response()
        }
        Err(error) => {
            lifecycle.fail(None);
            tracing::error!("Error heading blob: {}", error);
            (StatusCode::BAD_GATEWAY, format!("Error: {}", error)).into_response()
        }
    }
}
