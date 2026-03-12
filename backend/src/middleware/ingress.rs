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

use crate::infra;
use crate::services::request::ingress_host_allowed;

pub async fn ingress_guard_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::State(public_base_url): axum::extract::State<Arc<str>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if ingress_host_allowed(&req, addr, public_base_url.as_ref()) {
        return next.run(req).await;
    }

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<missing>");

    tracing::warn!(
        "Ingress host validation failed [IP: {}]: received host '{}', expected base URL '{}'",
        addr.ip(),
        host,
        public_base_url.as_ref()
    );

    infra::metrics::record_error("host_not_allowed");

    (
        StatusCode::FORBIDDEN,
        [("content-type", "text/plain; charset=utf-8")],
        format!(
            "Origin Host Not Allowed\n\nThis origin only accepts requests for the configured public host behind Cloudflare.\n\nReceived Host: {}\nConfigured shell.public_base_url: {}\n\nLocalhost loopback access remains allowed for development and container health checks.\n",
            host,
            public_base_url.as_ref()
        ),
    )
        .into_response()
}
