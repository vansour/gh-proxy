use gh_proxy::config::{GitHubConfig, Settings};
use gh_proxy::{AppState, cache, middleware, providers, services};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{info, warn};

pub(crate) fn log_startup(settings: &Settings) {
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
}

pub(crate) fn build_app_state(settings: Settings) -> Result<(AppState, SocketAddr), String> {
    let bind_addr: SocketAddr = settings
        .server
        .bind_addr()
        .parse()
        .map_err(|error| format!("invalid bind address: {}", error))?;
    let client = services::client::build_client(&settings.server);
    let github_config = GitHubConfig::new(&settings.auth.token, &settings.proxy);
    let auth_header = settings
        .auth
        .authorization_header()
        .map_err(|error| format!("invalid authorization header value: {}", error))?;

    let shutdown_manager = services::shutdown::ShutdownManager::new();
    let uptime_tracker = Arc::new(services::shutdown::UptimeTracker::new());
    let settings = Arc::new(settings);
    let download_semaphore = Arc::new(Semaphore::new(
        settings.server.max_concurrent_requests as usize,
    ));

    let cache_manager = Arc::new(cache::manager::CacheManager::new(settings.cache.clone()));
    let docker_proxy = Arc::new(providers::registry::DockerProxy::new(
        client.clone(),
        &settings.registry,
    ));
    let rate_limiter = Arc::new(middleware::RateLimiter::new(
        settings.rate_limit.max_requests,
        settings.rate_limit.window_secs,
    ));

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

    Ok((app_state, bind_addr))
}

pub(crate) fn log_server_ready(app_state: &AppState, bind_addr: SocketAddr) {
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
}
