//! Main proxy request handler.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, Method, Response, StatusCode, Uri};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use hyper::header;

use crate::cache::key::{CacheKey, request_variant_key};
use crate::cache::response_cache::CacheResult;
use crate::cache::response_cache::CachedResponse;
use crate::cache::utils::is_response_cacheable;

use crate::errors::{ProxyError, ProxyResult, classify_proxy_error, error_response};
use crate::infra;
use crate::middleware::{RequestLifecycle, RequestPermitGuard, mark_response_duration_recorded};
use crate::proxy::headers::{
    add_vary_header, apply_github_headers, fix_content_type_header, sanitize_request_headers,
    sanitize_response_headers,
};
use crate::proxy::resolver::{
    resolve_redirect_uri, resolve_target_uri_with_validation,
    should_disable_compression_for_request,
};
use crate::proxy::stream::ProxyBodyStream;
use crate::services::request::{
    derive_public_base_url, detect_client_country, detect_client_ip, trust_client_identity_headers,
};
use crate::services::text_processor::TextReplacementStream;
use crate::state::{AppState, ResponsePostProcessor};
use crate::utils::constants::*;

use tracing::{info, warn};

fn empty_response(status: StatusCode) -> Response<Body> {
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

/// Check if request body should be buffered.
fn should_buffer_request_body(method: &Method, headers: &HeaderMap) -> bool {
    if *method == Method::GET || *method == Method::HEAD {
        return false;
    }

    if let Some(cl) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        return cl <= MAX_MEMORY_BUFFER_SIZE;
    }

    false
}

/// Requests with Range semantics must bypass the shared response cache.
fn should_bypass_cache(headers: &HeaderMap) -> bool {
    headers.contains_key(header::RANGE)
}

/// Check if response needs text processing.
fn is_response_needs_text_processing(
    content_type: &Option<String>,
    target_uri: &Uri,
    shell_editor_enabled: bool,
) -> bool {
    if !shell_editor_enabled {
        return false;
    }
    let path = target_uri.path();
    if path.ends_with(".sh") || path.ends_with(".bash") || path.ends_with(".zsh") {
        return true;
    }
    if path.ends_with(".html") || path.ends_with(".htm") {
        return true;
    }
    if let Some(ct) = content_type {
        let ct_lower = ct.to_lowercase();
        if ct_lower.contains("text/") {
            return true;
        }
        if ct_lower.contains("text/html") || ct_lower.contains("application/xhtml") {
            return true;
        }
    }
    false
}

/// Get proxy URL from post-processor.
fn processor_proxy_url(processor: &Option<ResponsePostProcessor>) -> Option<&str> {
    match processor {
        Some(ResponsePostProcessor::ShellEditor { proxy_url }) => Some(proxy_url.as_ref()),
        None => None,
    }
}

/// Generate cache key from request
fn generate_cache_key(req: &Request<Body>, target_uri: &Uri) -> CacheKey {
    let host = target_uri.host().unwrap_or("unknown");
    let path = target_uri.path();
    let query = target_uri.query();
    let variant_key = request_variant_key(req.headers());

    // 根据路径模式确定缓存键类型
    if path.contains("/github/") || host.contains("github") {
        CacheKey::github_variant(host, path, query, variant_key)
    } else if let Some(rest) = path.strip_prefix("/v2/") {
        match crate::providers::registry::parse_v2_path(rest) {
            crate::providers::registry::V2Endpoint::Blob { name, digest } => {
                CacheKey::docker_blob_for(host, &name, &digest)
            }
            crate::providers::registry::V2Endpoint::Manifest { name, reference } => {
                CacheKey::docker_manifest_for(host, &name, &reference)
            }
            _ => CacheKey::generic_variant(req.method().as_str(), host, path, query, variant_key),
        }
    } else {
        CacheKey::generic_variant(req.method().as_str(), host, path, query, variant_key)
    }
}

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

    // Bypass common static paths
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

    // Generate cache key
    let cache_key = generate_cache_key(&req, &target_uri);

    // Check cache for GET requests
    if *req.method() == Method::GET && !bypass_cache {
        match state.cache_manager.get(&cache_key).await {
            CacheResult::Hit(cached) => {
                let cached = *cached;
                // Check for conditional requests
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
            CacheResult::Miss => {
                info!(
                    "Cache miss [IP: {}{}] -> {}",
                    client_ip, geo_info, target_uri
                );
            }
        }
    }

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
            let duration = start_time.elapsed();

            // Log slow requests
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
            warn!("Proxy error [IP: {}{}]: {}", client_ip, geo_info, error);
            infra::metrics::record_error(classify_proxy_error(&error));
            error_response(error)
        }
    }
}

/// Execute proxy request to upstream.
pub async fn proxy_request(
    state: &AppState,
    req: Request<Body>,
    target_uri: Uri,
    processor: Option<ResponsePostProcessor>,
    cache_key: CacheKey,
    bypass_cache: bool,
) -> ProxyResult<Response<Body>> {
    let mut lifecycle = RequestLifecycle::new(&state.shutdown_manager);
    let start = std::time::Instant::now();
    let size_limit_mb = state.settings.server.size_limit;
    let size_limit_bytes = size_limit_mb * 1024 * 1024;
    let mut current_uri = target_uri.clone();
    let initial_method = req.method().clone();
    let request_path = req.uri().path().to_string();

    let (mut req_parts, body) = req.into_parts();
    req_parts.uri = current_uri.clone();

    let request_size_limit_mb = state.settings.server.request_size_limit;
    let request_size_limit_bytes = request_size_limit_mb * 1024 * 1024;

    // Check Content-Length header first
    if let Some(len) = req_parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        && len > request_size_limit_bytes
    {
        let error = ProxyError::SizeExceeded(len / 1024 / 1024, request_size_limit_mb);
        lifecycle.fail(Some(&error));
        return Err(error);
    }

    let mut body_bytes: Option<Bytes> = None;
    let should_buffer = should_buffer_request_body(&initial_method, &req_parts.headers);

    let request_body = if should_buffer {
        let limited_body = http_body_util::Limited::new(body, request_size_limit_bytes as usize);
        match BodyExt::collect(limited_body).await {
            Ok(c) => {
                let b = c.to_bytes();
                body_bytes = Some(b.clone());
                Body::from(b)
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("length limit exceeded") {
                    let error = ProxyError::SizeExceeded(0, request_size_limit_mb);
                    lifecycle.fail(Some(&error));
                    return Err(error);
                }
                return Err(ProxyError::ProcessingError(err_str));
            }
        }
    } else {
        Body::from_stream(
            http_body_util::Limited::new(body, request_size_limit_bytes as usize)
                .into_data_stream()
                .map(|res| res.map_err(std::io::Error::other)),
        )
    };

    let mut req = Request::from_parts(req_parts, request_body);

    let disable_compression = if state.settings.shell.editor && processor.is_some() {
        should_disable_compression_for_request(&current_uri)
    } else {
        false
    };
    sanitize_request_headers(
        req.headers_mut(),
        disable_compression,
        Some(state.settings.ingress.auth_header_name.as_str()),
    );
    apply_github_headers(req.headers_mut(), &current_uri, state.auth_header.as_ref());

    // Fix for Issue: GitHub/S3 may ignore headers after redirect if we don't handle them carefully
    // We already do sanitization and apply_github_headers above.

    let sanitized_headers = Arc::new(req.headers().clone());

    let permit = state
        .download_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ProxyError::TooManyConcurrentRequests)?;
    infra::metrics::HTTP_ACTIVE_REQUESTS.inc();
    let mut permit_guard = RequestPermitGuard::new(permit, start);

    let mut redirect_count = 0;

    let response = loop {
        if redirect_count >= MAX_REDIRECTS {
            return Err(ProxyError::ProcessingError(
                "Too many redirects".to_string(),
            ));
        }

        let req_timeout = Duration::from_secs(state.settings.server.request_timeout_secs);
        let response = match tokio::time::timeout(req_timeout, state.client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(ProxyError::Http(Box::new(e))),
            Err(_) => return Err(ProxyError::ProcessingError("Request timeout".to_string())),
        };

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok());

            if let Some(loc) = location {
                let new_uri =
                    resolve_redirect_uri(&current_uri, loc, state.github_config.as_ref())?;
                if body_bytes.is_none()
                    && initial_method != Method::GET
                    && initial_method != Method::HEAD
                {
                    break response;
                }

                redirect_count += 1;
                current_uri = new_uri;
                let retry_body = body_bytes
                    .as_ref()
                    .map(|b| Body::from(b.clone()))
                    .unwrap_or(Body::empty());
                req = Request::builder()
                    .method(initial_method.clone())
                    .uri(current_uri.clone())
                    .body(retry_body)
                    .map_err(ProxyError::HttpBuilder)?;
                *req.headers_mut() = sanitized_headers.as_ref().clone();
                apply_github_headers(req.headers_mut(), &current_uri, state.auth_header.as_ref());
                continue;
            }
            break response;
        }
        break response;
    };

    let final_uri = current_uri.clone();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let content_length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    if let Some(len) = content_length
        && len > size_limit_bytes
    {
        let error = ProxyError::SizeExceeded(len / 1024 / 1024, size_limit_mb);
        lifecycle.fail(Some(&error));
        return Err(error);
    }

    let (mut parts, body) = response.into_parts();
    let shell_processing_enabled = state.settings.shell.editor && processor.is_some();
    let needs_text_processing = !status.is_redirection()
        && is_response_needs_text_processing(&content_type, &final_uri, shell_processing_enabled);
    let response_cacheable = !needs_text_processing
        && !bypass_cache
        && state
            .cache_manager
            .should_cache_request(&cache_key, &request_path)
        && is_response_cacheable(
            status.as_u16(),
            &parts.headers,
            state.cache_manager.config(),
        );

    if needs_text_processing {
        let proxy_url = processor_proxy_url(&processor).ok_or_else(|| {
            ProxyError::ProcessingError("response post-processor is missing proxy URL".to_string())
        })?;

        sanitize_response_headers(&mut parts.headers, true, true, true);
        fix_content_type_header(&mut parts.headers, &final_uri);

        add_vary_header(&mut parts.headers);
        parts.headers.remove(header::CONTENT_LENGTH);

        let body_stream = body
            .into_data_stream()
            .map(|res| res.map_err(std::io::Error::other));
        let processed_stream = TextReplacementStream::new(body_stream, proxy_url);

        let wrapped_stream =
            processed_stream.map(|res| res.map_err(|e| ProxyError::ProcessingError(e.to_string())));

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
        return Ok(response);
    }

    sanitize_response_headers(&mut parts.headers, false, false, false);
    fix_content_type_header(&mut parts.headers, &final_uri);

    // Add cache headers for CDN
    let cache_headers = state.cache_manager.build_cache_headers(
        content_type
            .as_deref()
            .unwrap_or("application/octet-stream"),
        status,
        response_cacheable,
    );
    for (name, value) in cache_headers {
        parts.headers.insert(name, value);
    }

    add_vary_header(&mut parts.headers);

    let cache_config = state.cache_manager.config();
    let should_buffer_for_cache = initial_method == Method::GET
        && response_cacheable
        && content_length
            .map(|len| len >= cache_config.min_object_size && len <= cache_config.max_object_size)
            .unwrap_or(false);

    if should_buffer_for_cache {
        let body_bytes = BodyExt::collect(http_body_util::Limited::new(
            Body::from_stream(
                body.into_data_stream()
                    .map(|r| r.map_err(std::io::Error::other)),
            ),
            (cache_config.max_object_size + 1) as usize,
        ))
        .await
        .map_err(|err| ProxyError::ProcessingError(err.to_string()))?
        .to_bytes();

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

        return Ok(Response::from_parts(parts, Body::from(body_bytes)));
    }

    let streaming_body = ProxyBodyStream::new(
        body.into_data_stream()
            .map(|r| r.map_err(|e| ProxyError::Http(Box::new(e))))
            .boxed(),
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
