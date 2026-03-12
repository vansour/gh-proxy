//! gh-proxy - High-performance GitHub file proxy server.
//!
//! This is main entry point for the application.

use clap::Parser;
use gh_proxy::config::{GitHubConfig, Settings};
use gh_proxy::{AppState, cache, infra, middleware, providers, router, services};
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

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "gh-proxy")]
#[command(about = "High-performance GitHub file proxy server", long_about = None)]
struct Args {
    /// Validate configuration and exit
    #[arg(long)]
    validate_config: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Load configuration
    let settings = Settings::load()?;
    infra::log::setup_tracing(&settings.log);

    if args.validate_config {
        println!("Configuration is valid!");
        return Ok(());
    }

    info!("Starting gh-proxy server v{}", env!("CARGO_PKG_VERSION"));
    info!("Log level: {}", settings.log.get_level());
    info!("Cache strategy: {:?}", settings.cache.strategy);

    if settings.shell.editor {
        info!("Shell editor mode enabled");
        if settings.shell.public_base_url.is_empty() {
            warn!(
                "shell.editor is enabled without shell.public_base_url; URL rewriting will only auto-enable for localhost requests"
            );
        }
    }
    if settings.shell.public_base_url.is_empty() {
        warn!(
            "Ingress host validation is disabled; set shell.public_base_url to pin the public Cloudflare host"
        );
    } else {
        info!(
            "Ingress host validation enabled for {}",
            settings.shell.public_base_url
        );
    }
    if settings.ingress.auth_header_enabled() {
        info!(
            "Origin auth enabled for non-loopback requests via header '{}'",
            settings.ingress.auth_header_name
        );
        info!(
            "Client IP/proto/country detection will trust Cloudflare/forwarded headers for authenticated remote requests"
        );
    } else {
        warn!(
            "Origin auth is disabled; direct-to-origin requests rely on host pinning and network perimeter only"
        );
        warn!(
            "Client identity attribution will ignore remote Cloudflare/forwarded headers until ingress auth is enabled"
        );
    }
    info!("CORS: Disabled for cross-origin browser access; same-origin UI only");

    // Build HTTP client
    let bind_addr: SocketAddr = settings.server.bind_addr().parse()?;
    let client = services::client::build_client(&settings.server);

    // Initialize configuration
    let github_config = GitHubConfig::new(&settings.auth.token, &settings.proxy);
    let auth_header = settings
        .auth
        .authorization_header()
        .map_err(|err| format!("invalid authorization header value: {}", err))?;

    // Initialize managers
    let shutdown_manager = services::shutdown::ShutdownManager::new();
    let uptime_tracker = Arc::new(services::shutdown::UptimeTracker::new());
    let settings = Arc::new(settings);
    let download_semaphore = Arc::new(Semaphore::new(
        settings.server.max_concurrent_requests as usize,
    ));

    // Create cache manager
    let cache_manager = Arc::new(cache::manager::CacheManager::new(settings.cache.clone()));

    // Create docker proxy with client clone before moving client
    let docker_proxy = Some(Arc::new(providers::registry::DockerProxy::new(
        client.clone(),
        &settings.registry,
    )));

    // Create rate limiter
    let rate_limiter = Arc::new(middleware::RateLimiter::new(
        settings.rate_limit.max_requests,
        settings.rate_limit.window_secs,
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
        cache_manager,
    };

    // Create router
    let app = router::create_router(app_state.clone());

    // Start server
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    app_state.shutdown_manager.mark_ready().await;

    info!("=================================================");
    info!("gh-proxy server listening on {}", bind_addr);
    info!("=================================================");
    info!(
        "Cache: {} (L1: moka, L2: Cloudflare CDN)",
        match app_state.settings.cache.strategy {
            cache::config::CacheStrategy::Disabled => "Disabled",
            cache::config::CacheStrategy::MemoryOnly => "Memory Only",
            cache::config::CacheStrategy::MemoryWithCdn => "Memory + CDN",
        }
    );

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
