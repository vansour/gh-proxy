//! gh-proxy - High-performance GitHub file proxy server.
//!
//! This is main entry point for the application.

mod shutdown_signal;
mod startup;

use clap::Parser;
use gh_proxy::config::Settings;
use gh_proxy::{infra, router};
use std::net::SocketAddr;
use tracing::info;

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

    let settings = Settings::load()?;
    infra::log::setup_tracing(&settings.log);

    if args.validate_config {
        println!("Configuration is valid!");
        return Ok(());
    }

    startup::log_startup(&settings);
    let (app_state, bind_addr) =
        startup::build_app_state(settings).map_err(std::io::Error::other)?;

    let app = router::create_router(app_state.clone());
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    app_state.shutdown_manager.mark_ready().await;

    startup::log_server_ready(&app_state, bind_addr);
    let shutdown_mgr = app_state.shutdown_manager.clone();
    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(listener, service)
        .with_graceful_shutdown(shutdown_signal::shutdown_signal(shutdown_mgr))
        .await?;

    info!("gh-proxy server shutting down gracefully");
    Ok(())
}
