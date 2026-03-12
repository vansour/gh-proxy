//! Application router configuration.

use axum::Router;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::{any, get, head, patch, post, put};
use std::sync::Arc;
use tower_http::compression::CompressionLayer;

use crate::api;
use crate::handlers;
use crate::infra;
use crate::middleware::{
    ingress_guard_middleware, origin_auth_middleware, rate_limit_middleware,
    request_metrics_middleware, response_hardening_middleware,
};
use crate::providers;
use crate::proxy;
use crate::state::AppState;

/// Create the application router with all routes configured.
pub fn create_router(app_state: AppState) -> Router {
    let ingress_public_base_url: Arc<str> =
        Arc::from(app_state.settings.shell.public_base_url.clone());
    let ingress_auth = Arc::new(app_state.settings.ingress.clone());
    let rate_limit_state = app_state.clone();

    Router::new()
        // Static pages
        .route("/", get(handlers::files::index))
        .route("/healthz", get(handlers::health::health_liveness))
        .route("/status", get(handlers::files::index))
        .route("/favicon.ico", get(handlers::files::serve_favicon))
        .route("/assets/{*path}", get(handlers::files::serve_static_asset))
        .route("/readyz", get(handlers::health::health_readiness))
        // API endpoints
        .route("/api/config", get(api::get_config))
        .route("/api/stats", get(api::get_stats))
        .route("/metrics", get(infra::metrics::metrics_handler))
        // GitHub proxy
        .route("/github/{*path}", any(providers::github::github_proxy))
        // Docker Registry V2 compatibility endpoints
        .route("/v2/", get(providers::registry::handle_v2_check))
        .route("/v2/{*rest}", get(providers::registry::v2_get))
        .route("/v2/{*rest}", head(providers::registry::v2_head))
        .route("/v2/{*rest}", post(providers::registry::v2_post))
        .route("/v2/{*rest}", patch(providers::registry::v2_patch))
        .route("/v2/{*rest}", put(providers::registry::v2_put))
        // Debug / registry utilities
        .route(
            "/debug/blob-info",
            get(providers::registry::debug_blob_info),
        )
        .route("/registry/healthz", get(providers::registry::healthz))
        // Fallback proxy handler
        .fallback(proxy::proxy_handler)
        .with_state(app_state)
        .layer(from_fn_with_state(
            ingress_public_base_url,
            ingress_guard_middleware,
        ))
        .layer(from_fn_with_state(ingress_auth, origin_auth_middleware))
        .layer(from_fn_with_state(rate_limit_state, rate_limit_middleware))
        .layer(from_fn(request_metrics_middleware))
        .layer(from_fn(response_hardening_middleware))
        // Compression for static files and API responses (Brotli > Gzip)
        .layer(CompressionLayer::new())
}
