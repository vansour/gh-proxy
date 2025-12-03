use std::{fs, path::Path};
use time::macros::format_description;
use tracing_subscriber::fmt::time::LocalTime;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn setup_tracing(log_config: &crate::config::LogConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_config.get_level()));

    // Time format: 2025-12-03T09:50:56
    let timer = LocalTime::new(format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second]"
    ));

    // Console layer (always active)
    let console_layer = fmt::layer()
        .with_timer(timer.clone())
        .with_writer(std::io::stdout)
        .with_target(false) // Remove target (e.g. "gh_proxy::handlers::...")
        .with_thread_ids(false)
        .with_thread_names(false);

    let log_file_path = log_config.log_file_path.trim();

    // Registry is the base subscriber
    let registry = tracing_subscriber::registry().with(filter);

    if log_file_path.is_empty() || log_file_path == "/dev/null" {
        if let Err(e) = registry.with(console_layer).try_init() {
            eprintln!("Warning: failed to init console logging: {}", e);
        }
        eprintln!("Logging initialized: console only");
        return;
    }

    // Setup file logging if configured
    if let Some(parent) = Path::new(log_file_path).parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!(
            "Warning: Failed to create log dir '{}': {}",
            parent.display(),
            e
        );
    }

    let parent = Path::new(log_file_path).parent().unwrap_or(Path::new("."));
    let file_stem = Path::new(log_file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("gh-proxy");

    let file_appender = tracing_appender::rolling::daily(parent, file_stem);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Leak the guard to ensure logging continues until process exit
    let _guard: &'static _ = Box::leak(Box::new(guard));

    let file_layer = fmt::layer()
        .with_timer(timer)
        .with_writer(non_blocking)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_ansi(false);

    // Compose layers: Console + File
    if let Err(e) = registry.with(console_layer).with(file_layer).try_init() {
        eprintln!("Warning: failed to init logging: {}", e);
    } else {
        eprintln!(
            "Logging initialized: console + file ({} with daily rotation)",
            log_file_path
        );
    }
}
