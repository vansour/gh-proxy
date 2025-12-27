//! Application router configuration.

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{any, get, head, post, put};
use std::sync::Arc;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};

use crate::api;
use crate::handlers;
use crate::infra;
use crate::middleware::rate_limit_middleware;
use crate::providers;
use crate::proxy;
use crate::state::AppState;

/// Create the application router with all routes configured.
pub fn create_router(app_state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any);

    let rate_limiter = Arc::clone(&app_state.rate_limiter);

    Router::new()
        // Static pages
        .route("/", get(handlers::files::index))
        .route("/healthz", get(handlers::health::health_liveness))
        .route("/style.css", get(handlers::files::serve_static_file))
        .route("/docker", get(handlers::files::serve_docker_index))
        .route("/script.js", get(handlers::files::serve_static_file))
        .route("/favicon.ico", get(handlers::files::serve_favicon))
        .route("/manifest.json", get(handlers::files::serve_static_file))
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
        .layer(from_fn_with_state(rate_limiter, rate_limit_middleware))
        .layer(cors)
        // Compression for static files and API responses (Brotli > Gzip)
        .layer(CompressionLayer::new())
}
