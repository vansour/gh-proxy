use super::cache::{generate_cache_key, should_bypass_cache};
use super::response::empty_response;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{Method, Response, StatusCode};
use hyper::header;
use tracing::{info, warn};

use crate::errors::{ProxyError, classify_proxy_error, error_response};
use crate::infra;
use crate::proxy::execute::proxy_request;
use crate::proxy::resolver::{
    resolve_target_uri_with_validation, should_disable_compression_for_request,
};
use crate::services::request::{
    derive_public_base_url, detect_client_country, detect_client_ip, trust_client_identity_headers,
};
use crate::state::{AppState, ResponsePostProcessor};
use crate::utils::constants::*;

/// Main fallback proxy handler.
pub async fn proxy_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    req: Request<Body>,
) -> Response<Body> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let start_time = Instant::now();
    let trust_forwarded_headers =
        trust_client_identity_headers(Some(addr), state.settings.ingress.auth_header_enabled());

    if matches!(
        path.as_str(),
        "/favicon.ico" | "/robots.txt" | "/apple-touch-icon.png" | "/.well-known/security.txt"
    ) {
        return empty_response(StatusCode::NOT_FOUND);
    }

    let client_ip = detect_client_ip(&req, Some(addr), trust_forwarded_headers);
    let proxy_url = derive_public_base_url(&req, &state.settings.shell.public_base_url);

    let geo_info = if let Some(country) = detect_client_country(&req, trust_forwarded_headers) {
        format!(" [{}]", country)
    } else {
        String::new()
    };

    if *req.method() != Method::GET && *req.method() != Method::HEAD {
        let error = ProxyError::MethodNotAllowed(format!(
            "The fallback proxy path '{}' does not accept {}.",
            path, method
        ));
        infra::metrics::record_error(classify_proxy_error(&error));
        return error_response(error);
    }

    let target_uri =
        match resolve_target_uri_with_validation(req.uri(), state.github_config.as_ref()) {
            Ok(uri) => uri,
            Err(error) => {
                info!(
                    "Rejected target [IP: {}{}]: {} ({})",
                    client_ip, geo_info, path, error
                );
                infra::metrics::record_error(classify_proxy_error(&error));
                return error_response(error);
            }
        };

    let bypass_cache = should_bypass_cache(req.headers());
    let cache_key = generate_cache_key(&req, &target_uri);
    let cache_fill_guard = if *req.method() == Method::GET && !bypass_cache {
        match state.cache_manager.get_or_reserve_fill(&cache_key).await {
            crate::cache::manager::CacheReservation::Hit(cached) => {
                let cached = *cached;
                if cached.matches_conditional(req.headers()) {
                    let mut response = empty_response(StatusCode::NOT_MODIFIED);
                    if let Some(etag) = cached.headers.get(header::ETAG).cloned() {
                        response.headers_mut().insert(header::ETAG, etag);
                    }
                    return response;
                }

                info!(
                    "Cache hit [IP: {}{}] -> {}",
                    client_ip, geo_info, target_uri
                );
                return cached.to_response();
            }
            crate::cache::manager::CacheReservation::Fill(guard) => {
                info!(
                    "Cache miss [IP: {}{}] -> {}",
                    client_ip, geo_info, target_uri
                );
                Some(guard)
            }
        }
    } else {
        None
    };

    let post_processor = if state.settings.shell.editor {
        proxy_url
            .as_ref()
            .map(|proxy_url| ResponsePostProcessor::ShellEditor {
                proxy_url: Arc::from(proxy_url.clone()),
            })
    } else {
        None
    };

    let streaming_tag =
        if post_processor.is_some() && should_disable_compression_for_request(&target_uri) {
            " [streaming]"
        } else {
            ""
        };

    info!(
        "Proxying request [IP: {}{}] -> {}{}",
        client_ip, geo_info, target_uri, streaming_tag
    );

    match proxy_request(
        &state,
        req,
        target_uri,
        post_processor,
        cache_key,
        bypass_cache,
    )
    .await
    {
        Ok(response) => {
            drop(cache_fill_guard);
            let duration = start_time.elapsed();

            if duration > SLOW_REQUEST_THRESHOLD {
                warn!(
                    "Slow request detected: {} {} took {:.2}s",
                    method,
                    path,
                    duration.as_secs_f64()
                );
            }

            response
        }
        Err(error) => {
            drop(cache_fill_guard);
            warn!("Proxy error [IP: {}{}]: {}", client_ip, geo_info, error);
            infra::metrics::record_error(classify_proxy_error(&error));
            error_response(error)
        }
    }
}
