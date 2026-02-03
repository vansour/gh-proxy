//! gh-proxy - High-performance GitHub file proxy server.
//!
//! This is the main entry point for the application.

use config::{GitHubConfig, Settings};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::Semaphore;
use tracing::{info, warn};

// Use Jemalloc for better memory management on Linux
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// Module declarations
mod api;
mod config;
mod errors;
mod handlers;
mod infra;
mod middleware;
mod providers;
mod proxy;
mod router;
mod services;
mod state;
mod utils;

// Re-exports for use in other modules
pub use errors::{ProxyError, ProxyResult};
pub use state::{AppState, ResponsePostProcessor};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let settings = Settings::load()?;
    infra::log::setup_tracing(&settings.log);

    info!("Starting gh-proxy server");
    info!("Log level: {}", settings.log.get_level());

    if settings.shell.editor {
        info!("Shell editor mode enabled");
    }
    info!("CORS: Enabled (allowing all origins)");

    // Build HTTP client
    let bind_addr: SocketAddr = settings.server.bind_addr().parse()?;
    let client = services::client::build_client(&settings.server);

    // Initialize configuration
    let github_config = GitHubConfig::new(&settings.auth.token, &settings.proxy);
    let auth_header = settings
        .auth
        .authorization_header()
        .map_err(|err| format!("invalid authorization header value: {err}"))?;

    // Initialize managers
    let shutdown_manager = services::shutdown::ShutdownManager::new();
    let uptime_tracker = Arc::new(services::shutdown::UptimeTracker::new());
    let settings = Arc::new(settings);
    let download_semaphore = Arc::new(Semaphore::new(
        settings.server.max_concurrent_requests as usize,
    ));

    // Create docker proxy with client clone before moving client
    let docker_proxy = Some(Arc::new(providers::registry::DockerProxy::new(
        client.clone(),
        &settings.registry.default,
    )));

    // Create rate limiter (adjustable via config)
    let rate_limiter = Arc::new(middleware::RateLimiter::new(
        settings.server.rate_limit_per_min as u32,
        60,
    ));

    // Build application state
    let app_state = AppState {
        settings: Arc::clone(&settings),
        github_config: Arc::new(github_config),
        client,
        shutdown_manager,
        uptime_tracker,
        auth_header,
        docker_proxy,
        download_semaphore,
        rate_limiter,
    };

    // Create router
    let app = router::create_router(app_state.clone());

    // Start server
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    app_state.shutdown_manager.mark_ready().await;

    info!("=================================================");
    info!("gh-proxy server listening on {}", bind_addr);
    info!("=================================================");

    let shutdown_mgr = app_state.shutdown_manager.clone();
    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(listener, service)
        .with_graceful_shutdown(shutdown_signal(shutdown_mgr))
        .await?;

    info!("gh-proxy server shutting down gracefully");
    Ok(())
}

/// Wait for shutdown signal and handle graceful shutdown.
async fn shutdown_signal(shutdown_mgr: services::shutdown::ShutdownManager) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal, initiating graceful shutdown...");
        },
        _ = terminate => {
            info!("Received SIGTERM signal, initiating graceful shutdown...");
        },
    }

    shutdown_mgr.initiate_shutdown().await;

    let shutdown_timeout = Duration::from_secs(30);
    let requests_completed = shutdown_mgr.wait_for_requests(shutdown_timeout).await;

    if requests_completed {
        info!("All active requests completed. Shutting down...");
    } else {
        warn!(
            "Graceful shutdown timeout. {} requests still active. Force shutting down...",
            shutdown_mgr.get_active_requests()
        );
    }

    shutdown_mgr.mark_stopped().await;
}
