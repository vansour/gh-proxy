use super::common::{
    begin_registry_request, cache_hit_response, manifest_cache_key,
    registry_host_not_allowed_response,
};
use crate::cache::manager::CacheReservation;
use crate::cache::response_cache::{CacheResult, CachedResponse};
use crate::cache::utils::is_response_cacheable;
use crate::infra;
use crate::proxy::headers::add_vary_header;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use std::sync::Arc;

pub(super) async fn get_manifest(
    State(state): State<AppState>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    let proxy = Arc::clone(&state.docker_proxy);
    let request_path = format!("/v2/{}/manifests/{}", name, reference);
    let cache_key = match manifest_cache_key(&proxy, &name, &reference) {
        Ok(cache_key) => cache_key,
        Err(error) => return registry_host_not_allowed_response(error),
    };

    let cache_fill_guard = match state.cache_manager.get_or_reserve_fill(&cache_key).await {
        CacheReservation::Hit(cached) => return cache_hit_response(*cached, false),
        CacheReservation::Fill(guard) => guard,
    };

    let (mut lifecycle, permit_guard) = match begin_registry_request(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    match proxy.get_manifest(&name, &reference).await {
        Ok((content_type, body)) => {
            let mut headers = HeaderMap::new();
            let ct_value = content_type
                .parse()
                .unwrap_or_else(|_| HeaderValue::from_static("application/json"));
            headers.insert(header::CONTENT_TYPE, ct_value);
            let body_bytes = Bytes::from(body.into_bytes());
            if let Ok(content_length) = body_bytes.len().to_string().parse() {
                headers.insert(header::CONTENT_LENGTH, content_length);
            }

            let response_cacheable = state
                .cache_manager
                .should_cache_request(&cache_key, &request_path)
                && is_response_cacheable(
                    StatusCode::OK.as_u16(),
                    &headers,
                    state.cache_manager.config(),
                );
            for (name, value) in state.cache_manager.build_cache_headers(
                &content_type,
                StatusCode::OK,
                response_cacheable,
            ) {
                headers.insert(name, value);
            }
            add_vary_header(&mut headers);

            if let Some(cached) = CachedResponse::from_buffered_parts(
                StatusCode::OK,
                headers.clone(),
                body_bytes.clone(),
                state.cache_manager.config(),
                cache_key.clone(),
                state.cache_manager.metrics(),
            ) {
                headers = cached.headers.clone();
                state.cache_manager.set(cache_key, cached).await;
            }

            infra::metrics::BYTES_TRANSFERRED_TOTAL.inc_by(body_bytes.len() as u64);
            lifecycle.success();
            drop(permit_guard);
            drop(cache_fill_guard);

            (StatusCode::OK, headers, Body::from(body_bytes)).into_response()
        }
        Err(error) => {
            lifecycle.fail(None);
            drop(cache_fill_guard);
            tracing::error!("Error getting manifest: {}", error);
            (StatusCode::BAD_GATEWAY, format!("Error: {}", error)).into_response()
        }
    }
}

pub(super) async fn head_manifest(
    State(state): State<AppState>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    let proxy = Arc::clone(&state.docker_proxy);
    let cache_key = match manifest_cache_key(&proxy, &name, &reference) {
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

    match proxy.head_manifest(&name, &reference).await {
        Ok((content_type, content_length)) => {
            let mut headers = HeaderMap::new();
            let ct_value = content_type
                .parse()
                .unwrap_or_else(|_| HeaderValue::from_static("application/json"));
            headers.insert(header::CONTENT_TYPE, ct_value);
            if let Ok(cl_value) = content_length.to_string().parse() {
                headers.insert(header::CONTENT_LENGTH, cl_value);
            }
            lifecycle.success();
            drop(permit_guard);
            (StatusCode::OK, headers).into_response()
        }
        Err(error) => {
            lifecycle.fail(None);
            tracing::error!("Error heading manifest: {}", error);
            (StatusCode::BAD_GATEWAY, format!("Error: {}", error)).into_response()
        }
    }
}
