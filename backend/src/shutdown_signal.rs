use gh_proxy::services;
use std::time::Duration;
use tokio::signal;
use tracing::{info, warn};

/// Wait for shutdown signal and handle graceful shutdown.
pub(crate) async fn shutdown_signal(shutdown_mgr: services::shutdown::ShutdownManager) {
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
