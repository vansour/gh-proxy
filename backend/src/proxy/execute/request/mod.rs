use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, Uri};
use bytes::Bytes;
use std::sync::Arc;

mod permit;
mod prepare;
mod redirects;

use crate::state::AppState;

pub(super) use permit::acquire_request_permit;
pub(super) use prepare::prepare_upstream_request;
pub(super) use redirects::execute_with_redirects;

pub(super) struct PreparedRequest {
    pub(super) req: Request<Body>,
    pub(super) current_uri: Uri,
    pub(super) initial_method: Method,
    pub(super) request_path: String,
    pub(super) body_bytes: Option<Bytes>,
    pub(super) sanitized_headers: Arc<HeaderMap>,
    pub(super) size_limit_mb: u64,
    pub(super) size_limit_bytes: u64,
}

pub(super) struct ExecutedRequest {
    pub response: hyper::Response<hyper::body::Incoming>,
    pub final_uri: Uri,
    pub initial_method: Method,
    pub request_path: String,
    pub size_limit_mb: u64,
    pub size_limit_bytes: u64,
}

pub(super) fn request_size_limits(state: &AppState) -> (u64, u64) {
    let request_size_limit_mb = state.settings.server.request_size_limit;
    let request_size_limit_bytes = request_size_limit_mb * 1024 * 1024;
    (request_size_limit_mb, request_size_limit_bytes)
}
