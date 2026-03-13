use super::resolve_github_target;
use crate::cache::key::{CacheKey, request_variant_key};
use crate::cache::manager::CacheReservation;
use crate::errors::{ProxyError, classify_proxy_error, error_response};
use crate::infra;
use crate::proxy::resolver::validate_target_uri;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{Method, Response, StatusCode},
};
use hyper::header;
use tracing::{error, info, instrument, warn};

#[instrument(skip_all, fields(path = %path))]
pub async fn github_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> Response<Body> {
    info!("GitHub proxy request: {} {}", req.method(), path);
    let method = req.method().clone();

    if *req.method() != Method::GET && *req.method() != Method::HEAD {
        let error = ProxyError::MethodNotAllowed(format!(
            "The `/github/*` endpoint does not accept {}.",
            method
        ));
        infra::metrics::record_error(classify_proxy_error(&error));
        return error_response(error);
    }

    let query = req.uri().query();
    match resolve_github_target(&path, query)
        .and_then(|target_uri| validate_target_uri(target_uri, state.github_config.as_ref()))
    {
        Ok(target_uri) => {
            info!("Resolved GitHub target: {}", target_uri);
            let cache_key = CacheKey::github_variant(
                target_uri.host().unwrap_or("github.com"),
                target_uri.path(),
                target_uri.query(),
                request_variant_key(req.headers()),
            );
            let bypass_cache = req.headers().contains_key(hyper::header::RANGE);
            let cache_fill_guard = if *req.method() == Method::GET && !bypass_cache {
                match state.cache_manager.get_or_reserve_fill(&cache_key).await {
                    CacheReservation::Hit(cached) => {
                        let cached = *cached;
                        if cached.matches_conditional(req.headers()) {
                            let mut response = axum::http::Response::new(Body::empty());
                            *response.status_mut() = StatusCode::NOT_MODIFIED;
                            if let Some(etag) = cached.headers.get(header::ETAG).cloned() {
                                response.headers_mut().insert(header::ETAG, etag);
                            }
                            return response;
                        }

                        return cached.to_response();
                    }
                    CacheReservation::Fill(guard) => Some(guard),
                }
            } else {
                None
            };
            match crate::proxy::proxy_request(
                &state,
                req,
                target_uri,
                None,
                cache_key,
                bypass_cache,
            )
            .await
            {
                Ok(response) => {
                    drop(cache_fill_guard);
                    info!("GitHub proxy success: status={}", response.status());
                    response
                }
                Err(err) => {
                    drop(cache_fill_guard);
                    error!("GitHub proxy failure: {}", err);
                    infra::metrics::record_error(classify_proxy_error(&err));
                    error_response(err)
                }
            }
        }
        Err(ProxyError::InvalidTarget(msg)) => {
            warn!("Invalid GitHub target: {}", msg);
            let error = ProxyError::InvalidRequest(format!(
                "`/github/*` only accepts repository-relative GitHub paths.\n\n\
Examples:\n\
- /github/owner/repo/main/file.txt\n\
- /github/owner/repo/releases/download/v1.0.0/archive.tar.gz\n\n\
To proxy a full GitHub URL, use the fallback path instead:\n\
- /https://github.com/owner/repo/blob/main/file.txt\n\n\
Details: {}",
                msg
            ));
            infra::metrics::record_error(classify_proxy_error(&error));
            error_response(error)
        }
        Err(err) => {
            error!("GitHub target resolution error: {}", err);
            infra::metrics::record_error(classify_proxy_error(&err));
            error_response(err)
        }
    }
}
