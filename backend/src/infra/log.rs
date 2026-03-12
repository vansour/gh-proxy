use time::macros::format_description;
use tracing_subscriber::fmt::time::LocalTime;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn setup_tracing(log_config: &crate::config::LogConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_config.get_level()));

    let timer = LocalTime::new(format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second]"
    ));

    let console_layer = fmt::layer()
        .with_timer(timer)
        .with_writer(std::io::stdout)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false);

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .try_init();

    eprintln!("Logging initialized: console only");
}
