use std::{fs, path::Path};

use tracing_appender;
use tracing_subscriber::fmt::time::LocalTime;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Initialize logging according to configuration using `tracing_appender`.
pub fn setup_tracing(log_config: &crate::config::LogConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_config.get_level()));

    // We'll create a single fmt layer that writes to both file and stdout using a custom MakeWriter.

    let log_file_path = log_config.log_file_path.trim();

    // If no log file configured or explicitly /dev/null, only use console
    if log_file_path.is_empty() || log_file_path == "/dev/null" {
        let console_layer = fmt::layer()
            .with_timer(LocalTime::rfc_3339())
            .with_writer(std::io::stdout)
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false);

        if let Err(e) = tracing_subscriber::registry()
            .with(filter)
            .with(console_layer)
            .try_init()
        {
            eprintln!(
                "Warning: failed to initialize tracing subscriber (already set?): {}",
                e
            );
        }
        eprintln!("Logging initialized: console only");
        return;
    }

    // Ensure parent directory exists
    if let Some(parent) = Path::new(log_file_path).parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!(
                    "Warning: Failed to create log directory '{}': {}",
                    parent.display(),
                    e
                );
            } else {
                eprintln!("Log directory created/verified: {}", parent.display());
            }
        }
    }

    // Derive directory and file stem for rolling appender
    let parent = Path::new(log_file_path)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or(".");

    let file_stem = Path::new(log_file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("gh-proxy");

    // Use daily rotation. tracing_appender does not support size-based rotation out-of-the-box.
    // If you need size-based rotation, we can add an external rotation utility or keep flexi_logger.
    let file_appender = tracing_appender::rolling::daily(parent, file_stem);

    // Create a non-blocking, background worker and keep the guard alive for the lifetime of the program.
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    // Leak the guard so it lives for the whole program lifetime (acceptable for long-running service).
    let _guard: &'static _ = Box::leak(Box::new(guard));

    // Compose a single layer using a custom MakeWriter that tees to file and stdout.
    // Implement a small Tee writer to forward writes to both destinations.
    use std::io::{self, Write};

    struct TeeMakeWriter {
        file: tracing_appender::non_blocking::NonBlocking,
    }

    struct TeeWriter<'a> {
        file_writer: Box<dyn Write + Send + 'a>,
        stdout_writer: Box<dyn Write + Send + 'a>,
    }

    impl<'a> Write for TeeWriter<'a> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // Attempt to write to both. Return the result of the file write if successful,
            // otherwise propagate the stdout error (or file error if stdout succeeded).
            let file_res = self.file_writer.write(buf);
            let stdout_res = self.stdout_writer.write(buf);

            match (file_res, stdout_res) {
                (Ok(n), Ok(_)) => Ok(n),
                (Ok(n), Err(_)) => Ok(n),
                (Err(e), Ok(_)) => Err(e),
                (Err(e), Err(_)) => Err(e),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            let f1 = self.file_writer.flush();
            let f2 = self.stdout_writer.flush();
            f1.and(f2)
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TeeMakeWriter {
        type Writer = TeeWriter<'a>;

        fn make_writer(&'a self) -> Self::Writer {
            let fw = self.file.make_writer();
            let sw = std::io::stdout();
            TeeWriter {
                file_writer: Box::new(fw),
                stdout_writer: Box::new(sw),
            }
        }
    }

    let tee = TeeMakeWriter { file: non_blocking };
    let combined_layer = fmt::layer()
        .with_timer(LocalTime::rfc_3339())
        .with_writer(tee)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false);

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(combined_layer);

    if let Err(e) = subscriber.try_init() {
        eprintln!(
            "Warning: failed to initialize tracing subscriber (already set?): {}",
            e
        );
    } else {
        eprintln!(
            "Logging initialized: tracing_appender -> {}/{} (daily rotation)",
            parent, file_stem
        );
    }
}
