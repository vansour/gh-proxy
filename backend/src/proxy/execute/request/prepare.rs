use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, Uri, header};
use futures_util::StreamExt;
use http_body_util::BodyExt;

use crate::errors::{ProxyError, ProxyResult};
use crate::proxy::headers::{apply_github_headers, sanitize_request_headers};
use crate::proxy::resolver::should_disable_compression_for_request;
use crate::state::AppState;
use crate::utils::constants::MAX_MEMORY_BUFFER_SIZE;

use super::{PreparedRequest, request_size_limits};

fn should_buffer_request_body(method: &Method, headers: &HeaderMap) -> bool {
    if *method == Method::GET || *method == Method::HEAD {
        return false;
    }

    if let Some(content_length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        return content_length <= MAX_MEMORY_BUFFER_SIZE;
    }

    false
}

pub(in crate::proxy::execute) async fn prepare_upstream_request(
    state: &AppState,
    req: Request<Body>,
    target_uri: Uri,
    enable_post_processing: bool,
) -> ProxyResult<PreparedRequest> {
    let size_limit_mb = state.settings.server.size_limit;
    let size_limit_bytes = size_limit_mb * 1024 * 1024;
    let request_path = req.uri().path().to_string();
    let (request_size_limit_mb, request_size_limit_bytes) = request_size_limits(state);
    let current_uri = target_uri.clone();
    let initial_method = req.method().clone();

    let (mut req_parts, body) = req.into_parts();
    req_parts.uri = current_uri.clone();

    if let Some(content_length) = req_parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        && content_length > request_size_limit_bytes
    {
        return Err(ProxyError::SizeExceeded(
            content_length / 1024 / 1024,
            request_size_limit_mb,
        ));
    }

    let mut body_bytes = None;
    let request_body = if should_buffer_request_body(&initial_method, &req_parts.headers) {
        let limited_body = http_body_util::Limited::new(body, request_size_limit_bytes as usize);
        match BodyExt::collect(limited_body).await {
            Ok(collected) => {
                let buffered = collected.to_bytes();
                body_bytes = Some(buffered.clone());
                Body::from(buffered)
            }
            Err(error) => {
                let error_text = error.to_string();
                if error_text.contains("length limit exceeded") {
                    return Err(ProxyError::SizeExceeded(0, request_size_limit_mb));
                }
                return Err(ProxyError::ProcessingError(error_text));
            }
        }
    } else {
        Body::from_stream(
            http_body_util::Limited::new(body, request_size_limit_bytes as usize)
                .into_data_stream()
                .map(|result| result.map_err(std::io::Error::other)),
        )
    };

    let mut req = Request::from_parts(req_parts, request_body);
    let disable_compression = if state.settings.shell.editor && enable_post_processing {
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

    Ok(PreparedRequest {
        sanitized_headers: std::sync::Arc::new(req.headers().clone()),
        req,
        current_uri,
        initial_method,
        request_path,
        body_bytes,
        size_limit_mb,
        size_limit_bytes,
    })
}
