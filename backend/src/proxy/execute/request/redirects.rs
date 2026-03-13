use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, header};

use crate::errors::{ProxyError, ProxyResult};
use crate::proxy::headers::apply_github_headers;
use crate::proxy::resolver::resolve_redirect_uri;
use crate::state::AppState;
use crate::utils::constants::MAX_REDIRECTS;

use super::{ExecutedRequest, PreparedRequest};

fn finalize(
    prepared: PreparedRequest,
    response: hyper::Response<hyper::body::Incoming>,
) -> ExecutedRequest {
    ExecutedRequest {
        response,
        final_uri: prepared.current_uri,
        initial_method: prepared.initial_method,
        request_path: prepared.request_path,
        size_limit_mb: prepared.size_limit_mb,
        size_limit_bytes: prepared.size_limit_bytes,
    }
}

fn rebuild_redirect_request(
    state: &AppState,
    prepared: &mut PreparedRequest,
) -> Result<(), ProxyError> {
    let retry_body = prepared
        .body_bytes
        .as_ref()
        .map(|bytes| Body::from(bytes.clone()))
        .unwrap_or(Body::empty());
    prepared.req = Request::builder()
        .method(prepared.initial_method.clone())
        .uri(prepared.current_uri.clone())
        .body(retry_body)
        .map_err(ProxyError::HttpBuilder)?;
    *prepared.req.headers_mut() = prepared.sanitized_headers.as_ref().clone();
    apply_github_headers(
        prepared.req.headers_mut(),
        &prepared.current_uri,
        state.auth_header.as_ref(),
    );
    Ok(())
}

pub(in crate::proxy::execute) async fn execute_with_redirects(
    state: &AppState,
    mut prepared: PreparedRequest,
) -> ProxyResult<ExecutedRequest> {
    let mut redirect_count = 0;

    loop {
        if redirect_count >= MAX_REDIRECTS {
            return Err(ProxyError::ProcessingError(
                "Too many redirects".to_string(),
            ));
        }

        let request_timeout = Duration::from_secs(state.settings.server.request_timeout_secs);
        let request = std::mem::replace(&mut prepared.req, Request::new(Body::empty()));
        let response =
            match tokio::time::timeout(request_timeout, state.client.request(request)).await {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => return Err(ProxyError::Http(Box::new(error))),
                Err(_) => return Err(ProxyError::ProcessingError("Request timeout".to_string())),
            };

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok());

            if let Some(location) = location {
                let new_uri = resolve_redirect_uri(
                    &prepared.current_uri,
                    location,
                    state.github_config.as_ref(),
                )?;
                if prepared.body_bytes.is_none()
                    && prepared.initial_method != Method::GET
                    && prepared.initial_method != Method::HEAD
                {
                    return Ok(finalize(prepared, response));
                }

                redirect_count += 1;
                prepared.current_uri = new_uri;
                rebuild_redirect_request(state, &mut prepared)?;
                continue;
            }
        }

        return Ok(finalize(prepared, response));
    }
}
