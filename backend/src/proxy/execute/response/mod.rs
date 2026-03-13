use axum::body::Body;
use axum::http::{Method, Response, Uri, header};

use crate::cache::key::CacheKey;
use crate::errors::{ProxyError, ProxyResult};
use crate::middleware::RequestLifecycle;
use crate::state::{AppState, ResponsePostProcessor};

use super::request::ExecutedRequest;

mod buffered;
mod streaming;
mod text;

fn size_limit_error(actual_bytes: u64, size_limit_mb: u64) -> ProxyError {
    ProxyError::SizeExceeded(actual_bytes / 1024 / 1024, size_limit_mb)
}

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
    if let Some(content_type) = content_type {
        let content_type = content_type.to_lowercase();
        if content_type.contains("text/") {
            return true;
        }
        if content_type.contains("text/html") || content_type.contains("application/xhtml") {
            return true;
        }
    }
    false
}

pub(super) fn processor_proxy_url(processor: &Option<ResponsePostProcessor>) -> Option<&str> {
    match processor.as_ref() {
        Some(ResponsePostProcessor::ShellEditor { proxy_url }) => Some(proxy_url.as_ref()),
        None => None,
    }
}

pub(super) async fn build_proxy_response(
    state: &AppState,
    executed: ExecutedRequest,
    processor: Option<ResponsePostProcessor>,
    cache_key: CacheKey,
    bypass_cache: bool,
    mut lifecycle: RequestLifecycle,
    permit_guard: crate::middleware::RequestPermitGuard,
) -> ProxyResult<Response<Body>> {
    let ExecutedRequest {
        response,
        final_uri,
        initial_method,
        request_path,
        size_limit_mb,
        size_limit_bytes,
    } = executed;

    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let content_length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());

    if let Some(content_length) = content_length
        && content_length > size_limit_bytes
    {
        let error = size_limit_error(content_length, size_limit_mb);
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
        && crate::cache::utils::is_response_cacheable(
            status.as_u16(),
            &parts.headers,
            state.cache_manager.config(),
        );

    if needs_text_processing {
        return text::text_processed_response(
            state,
            parts,
            body,
            &final_uri,
            processor,
            lifecycle,
            permit_guard,
            size_limit_bytes,
            size_limit_mb,
        );
    }

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

    crate::proxy::headers::sanitize_response_headers(&mut parts.headers, false, false, false);
    crate::proxy::headers::fix_content_type_header(&mut parts.headers, &final_uri);
    crate::proxy::headers::add_vary_header(&mut parts.headers);

    let cache_config = state.cache_manager.config();
    let should_buffer_for_cache = initial_method == Method::GET
        && response_cacheable
        && content_length
            .map(|len| len >= cache_config.min_object_size && len <= cache_config.max_object_size)
            .unwrap_or(false);

    if should_buffer_for_cache {
        return buffered::buffered_response(
            state,
            parts,
            body,
            status,
            cache_key,
            lifecycle,
            permit_guard,
            size_limit_bytes,
            size_limit_mb,
        )
        .await;
    }

    Ok(streaming::streaming_response(
        parts,
        body,
        lifecycle,
        permit_guard,
        size_limit_bytes,
        size_limit_mb,
        state.settings.shell.editor,
    ))
}
