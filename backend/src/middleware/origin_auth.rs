use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use hyper::StatusCode;

use crate::config::IngressConfig;
use crate::infra;
use crate::services::request::origin_auth_allowed;

pub async fn origin_auth_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::State(config): axum::extract::State<Arc<IngressConfig>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if origin_auth_allowed(
        req.headers(),
        addr,
        &config.auth_header_name,
        &config.auth_header_value,
    ) {
        return next.run(req).await;
    }

    infra::metrics::record_error("origin_auth_failed");

    (
        StatusCode::FORBIDDEN,
        [("content-type", "text/plain; charset=utf-8")],
        format!(
            "Origin Access Authentication Failed\n\nThis origin requires the configured '{}' header for non-loopback requests behind Cloudflare.\n\nLoopback access remains allowed for local development and container probes.\n",
            config.auth_header_name
        ),
    )
        .into_response()
}
