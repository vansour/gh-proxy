//! Main proxy request handler.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, Response, StatusCode, Uri};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use hyper::header;

use crate::errors::{ProxyError, ProxyResult, error_response};
use crate::infra;
use crate::middleware::{RequestLifecycle, RequestPermitGuard};
use crate::proxy::headers::{
    apply_github_headers, fix_content_type_header, sanitize_request_headers,
    sanitize_response_headers,
};
use crate::proxy::resolver::{
    resolve_target_uri_with_validation, should_disable_compression_for_request,
};
use crate::proxy::stream::ProxyBodyStream;
use crate::services::request::detect_client_protocol;
use crate::services::text_processor::TextReplacementStream;
use crate::state::{AppState, ResponsePostProcessor};

use tracing::{info, warn};

/// Get the real client IP from headers.
fn get_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.split(',').next())
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Get client country from Cloudflare header.
fn get_client_country(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cf-ipcountry")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

/// Check if request body should be buffered.
fn should_buffer_request_body(method: &Method, headers: &HeaderMap) -> bool {
    if headers.contains_key(header::CONTENT_LENGTH)
        || headers.contains_key(header::TRANSFER_ENCODING)
    {
        return true;
    }
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
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

/// Main fallback proxy handler.
pub async fn proxy_handler(State(state): State<AppState>, req: Request<Body>) -> Response<Body> {
    let path = req.uri().path();
    if matches!(
        path,
        "/favicon.ico" | "/robots.txt" | "/apple-touch-icon.png" | "/.well-known/security.txt"
    ) {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    }
    let proxy_host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080")
        .to_string();
    let client_ip = get_client_ip(req.headers());
    let proxy_scheme = detect_client_protocol(&req);
    let proxy_url = format!("{}://{}", proxy_scheme, proxy_host);

    let geo_info = if let Some(country) = get_client_country(req.headers()) {
        format!(" [{}]", country)
    } else {
        String::new()
    };

    let target_uri =
        match resolve_target_uri_with_validation(req.uri(), state.github_config.as_ref()) {
            Ok(uri) => uri,
            Err(_) => {
                info!("Invalid target [IP: {}{}]: {}", client_ip, geo_info, path);
                let error_msg = format!("404 Not Found\n\nInvalid target: {}\n", path);
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from(error_msg))
                    .unwrap();
            }
        };

    let post_processor = if state.settings.shell.editor {
        Some(ResponsePostProcessor::ShellEditor {
            proxy_url: Arc::from(proxy_url.clone()),
        })
    } else {
        None
    };

    let streaming_tag =
        if state.settings.shell.editor && should_disable_compression_for_request(&target_uri) {
            " [streaming]"
        } else {
            ""
        };

    info!(
        "Proxying request [IP: {}{}] -> {}{}",
        client_ip, geo_info, target_uri, streaming_tag
    );

    match proxy_request(&state, req, target_uri, post_processor).await {
        Ok(response) => response,
        Err(error) => {
            warn!("Proxy error [IP: {}{}]: {}", client_ip, geo_info, error);
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
) -> ProxyResult<Response<Body>> {
    let mut lifecycle = RequestLifecycle::new(&state.shutdown_manager);
    let start = std::time::Instant::now();
    let size_limit_mb = state.settings.server.size_limit;
    let size_limit_bytes = size_limit_mb * 1024 * 1024;
    let mut current_uri = target_uri.clone();
    let initial_method = req.method().clone();

    let (mut req_parts, body) = req.into_parts();
    req_parts.uri = current_uri.clone();

    let mut body_bytes: Option<Bytes> = None;
    let should_buffer = should_buffer_request_body(&initial_method, &req_parts.headers);
    let request_body = if should_buffer {
        match body.collect().await {
            Ok(c) => {
                let b = c.to_bytes();
                body_bytes = Some(b.clone());
                Body::from(b)
            }
            Err(e) => return Err(ProxyError::ProcessingError(e.to_string())),
        }
    } else {
        Body::empty()
    };

    let mut req = Request::from_parts(req_parts, request_body);

    let disable_compression = if state.settings.shell.editor && processor.is_some() {
        should_disable_compression_for_request(&current_uri)
    } else {
        false
    };
    sanitize_request_headers(req.headers_mut(), disable_compression);
    apply_github_headers(req.headers_mut(), &current_uri, state.auth_header.as_ref());
    let sanitized_headers = Arc::new(req.headers().clone());

    let permit = state
        .download_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ProxyError::TooManyConcurrentRequests)?;
    infra::metrics::HTTP_ACTIVE_REQUESTS.inc();
    let mut permit_guard = RequestPermitGuard::new(permit, start);

    let response = loop {
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
            #[allow(clippy::collapsible_if)]
            if let Some(loc) = location {
                if let Ok(new_uri) = loc.parse::<Uri>() {
                    current_uri = new_uri;
                    let retry_body = body_bytes
                        .as_ref()
                        .map(|b| Body::from(b.clone()))
                        .unwrap_or(Body::empty());
                    req = Request::builder()
                        .method(initial_method.clone())
                        .uri(current_uri.clone())
                        .body(retry_body)
                        .unwrap();
                    *req.headers_mut() = sanitized_headers.as_ref().clone();
                    apply_github_headers(
                        req.headers_mut(),
                        &current_uri,
                        state.auth_header.as_ref(),
                    );
                    continue;
                }
            }
            break response;
        }
        break response;
    };

    let status = response.status();
    infra::metrics::HTTP_REQUESTS_TOTAL.inc();

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
        && is_response_needs_text_processing(&content_type, &target_uri, shell_processing_enabled);

    if needs_text_processing {
        let proxy_url = processor_proxy_url(&processor).unwrap();

        sanitize_response_headers(&mut parts.headers, true, true, true);
        fix_content_type_header(&mut parts.headers, &target_uri);
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
        );

        return Ok(Response::from_parts(
            parts,
            Body::from_stream(streaming_body),
        ));
    }

    sanitize_response_headers(&mut parts.headers, false, false, false);
    fix_content_type_header(&mut parts.headers, &target_uri);

    let streaming_body = ProxyBodyStream::new(
        body.into_data_stream()
            .map(|r| r.map_err(|e| ProxyError::Http(Box::new(e))))
            .boxed(),
        lifecycle,
        size_limit_bytes,
        size_limit_mb,
        permit_guard.take_start_time(),
        permit_guard.take_permit(),
    );

    Ok(Response::from_parts(
        parts,
        Body::from_stream(streaming_body),
    ))
}
