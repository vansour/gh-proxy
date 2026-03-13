use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, Response, Uri};

use crate::cache::key::CacheKey;
use crate::errors::{ProxyError, ProxyResult};
use crate::middleware::RequestLifecycle;
use crate::state::{AppState, ResponsePostProcessor};

mod request;
mod response;

fn fail_request<T>(lifecycle: &mut RequestLifecycle, error: ProxyError) -> ProxyResult<T> {
    lifecycle.fail(Some(&error));
    Err(error)
}

pub async fn proxy_request(
    state: &AppState,
    req: Request<Body>,
    target_uri: Uri,
    processor: Option<ResponsePostProcessor>,
    cache_key: CacheKey,
    bypass_cache: bool,
) -> ProxyResult<Response<Body>> {
    let mut lifecycle = RequestLifecycle::new(&state.shutdown_manager);
    let start = Instant::now();

    let prepared = match request::prepare_upstream_request(
        state,
        req,
        target_uri,
        processor.is_some(),
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => return fail_request(&mut lifecycle, error),
    };

    let permit_guard = match request::acquire_request_permit(state, start).await {
        Ok(permit_guard) => permit_guard,
        Err(error) => return fail_request(&mut lifecycle, error),
    };

    let executed = match request::execute_with_redirects(state, prepared).await {
        Ok(executed) => executed,
        Err(error) => return fail_request(&mut lifecycle, error),
    };

    response::build_proxy_response(
        state,
        executed,
        processor,
        cache_key,
        bypass_cache,
        lifecycle,
        permit_guard,
    )
    .await
}
