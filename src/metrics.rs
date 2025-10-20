// Metrics and tracing for observability
//
// This module provides:
// - Prometheus metrics collection for RED monitoring (Rate/Errors/Duration)
// - Request tracing with timing information
// - Performance metrics per endpoint
// - System metrics (uptime, connections, etc.)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;

/// Metrics collector for RED monitoring
#[derive(Clone)]
pub struct MetricsCollector {
    // Request counters
    total_requests: Arc<AtomicU64>,
    successful_requests: Arc<AtomicU64>,
    failed_requests: Arc<AtomicU64>,

    // Request size metrics (bytes)
    total_bytes_received: Arc<AtomicU64>,
    total_bytes_sent: Arc<AtomicU64>,

    // Timing metrics
    total_request_duration_ms: Arc<AtomicU64>,
    max_request_duration_ms: Arc<AtomicU64>,

    // Per-endpoint metrics
    github_requests: Arc<AtomicU64>,
    fallback_requests: Arc<AtomicU64>,

    // Error counts by type
    proxy_errors: Arc<AtomicU64>,
    timeout_errors: Arc<AtomicU64>,
    size_exceeded_errors: Arc<AtomicU64>,
    access_denied_errors: Arc<AtomicU64>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            successful_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            total_bytes_received: Arc::new(AtomicU64::new(0)),
            total_bytes_sent: Arc::new(AtomicU64::new(0)),
            total_request_duration_ms: Arc::new(AtomicU64::new(0)),
            max_request_duration_ms: Arc::new(AtomicU64::new(0)),
            github_requests: Arc::new(AtomicU64::new(0)),
            fallback_requests: Arc::new(AtomicU64::new(0)),
            proxy_errors: Arc::new(AtomicU64::new(0)),
            timeout_errors: Arc::new(AtomicU64::new(0)),
            size_exceeded_errors: Arc::new(AtomicU64::new(0)),
            access_denied_errors: Arc::new(AtomicU64::new(0)),
        }
    }

    // ==================== Request tracking ====================

    /// Record a new request
    pub fn record_request_start(&self) -> RequestMetrics {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        RequestMetrics {
            start_time: Instant::now(),
            collector: self.clone(),
        }
    }

    /// Record request completion
    pub fn record_request_success(&self, duration_ms: u64, bytes_sent: u64) {
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        self.total_request_duration_ms
            .fetch_add(duration_ms, Ordering::Relaxed);
        self.total_bytes_sent
            .fetch_add(bytes_sent, Ordering::Relaxed);

        // Update max duration
        let mut current_max = self.max_request_duration_ms.load(Ordering::Relaxed);
        while duration_ms > current_max {
            match self.max_request_duration_ms.compare_exchange(
                current_max,
                duration_ms,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_max = actual,
            }
        }
    }

    /// Record request failure
    pub fn record_request_error(&self, duration_ms: u64) {
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
        self.total_request_duration_ms
            .fetch_add(duration_ms, Ordering::Relaxed);
    }

    /// Record incoming request size
    pub fn record_bytes_received(&self, bytes: u64) {
        self.total_bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
    }

    // ==================== Endpoint tracking ====================

    /// Record GitHub proxy request
    pub fn record_github_request(&self) {
        self.github_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record fallback proxy request
    pub fn record_fallback_request(&self) {
        self.fallback_requests.fetch_add(1, Ordering::Relaxed);
    }

    // ==================== Error tracking ====================

    /// Record a proxy error
    pub fn record_proxy_error(&self) {
        self.proxy_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a timeout error
    pub fn record_timeout_error(&self) {
        self.timeout_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a size exceeded error
    pub fn record_size_exceeded_error(&self) {
        self.size_exceeded_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an access denied error
    pub fn record_access_denied_error(&self) {
        self.access_denied_errors.fetch_add(1, Ordering::Relaxed);
    }

    // ==================== Metrics retrieval ====================

    /// Get all metrics as Prometheus format string
    pub fn as_prometheus_metrics(&self) -> String {
        let total = self.total_requests.load(Ordering::Relaxed);
        let successful = self.successful_requests.load(Ordering::Relaxed);
        let failed = self.failed_requests.load(Ordering::Relaxed);
        let bytes_received = self.total_bytes_received.load(Ordering::Relaxed);
        let bytes_sent = self.total_bytes_sent.load(Ordering::Relaxed);
        let total_duration = self.total_request_duration_ms.load(Ordering::Relaxed);
        let max_duration = self.max_request_duration_ms.load(Ordering::Relaxed);
        let github = self.github_requests.load(Ordering::Relaxed);
        let fallback = self.fallback_requests.load(Ordering::Relaxed);
        let proxy_err = self.proxy_errors.load(Ordering::Relaxed);
        let timeout_err = self.timeout_errors.load(Ordering::Relaxed);
        let size_err = self.size_exceeded_errors.load(Ordering::Relaxed);
        let access_err = self.access_denied_errors.load(Ordering::Relaxed);

        let avg_duration = if total > 0 { total_duration / total } else { 0 };

        let error_rate = if total > 0 {
            (failed as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        format!(
            "# HELP gh_proxy_requests_total Total number of requests\n\
            # TYPE gh_proxy_requests_total counter\n\
            gh_proxy_requests_total {}\n\
            \n\
            # HELP gh_proxy_requests_successful Successful requests\n\
            # TYPE gh_proxy_requests_successful counter\n\
            gh_proxy_requests_successful {}\n\
            \n\
            # HELP gh_proxy_requests_failed Failed requests\n\
            # TYPE gh_proxy_requests_failed counter\n\
            gh_proxy_requests_failed {}\n\
            \n\
            # HELP gh_proxy_request_duration_ms_avg Average request duration in milliseconds\n\
            # TYPE gh_proxy_request_duration_ms_avg gauge\n\
            gh_proxy_request_duration_ms_avg {}\n\
            \n\
            # HELP gh_proxy_request_duration_ms_max Max request duration in milliseconds\n\
            # TYPE gh_proxy_request_duration_ms_max gauge\n\
            gh_proxy_request_duration_ms_max {}\n\
            \n\
            # HELP gh_proxy_bytes_received_total Total bytes received\n\
            # TYPE gh_proxy_bytes_received_total counter\n\
            gh_proxy_bytes_received_total {}\n\
            \n\
            # HELP gh_proxy_bytes_sent_total Total bytes sent\n\
            # TYPE gh_proxy_bytes_sent_total counter\n\
            gh_proxy_bytes_sent_total {}\n\
            \n\
            # HELP gh_proxy_error_rate_percent Error rate percentage\n\
            # TYPE gh_proxy_error_rate_percent gauge\n\
            gh_proxy_error_rate_percent {:.2}\n\
            \n\
            # HELP gh_proxy_github_requests GitHub proxy requests\n\
            # TYPE gh_proxy_github_requests counter\n\
            gh_proxy_github_requests {}\n\
            \n\
            # HELP gh_proxy_fallback_requests Fallback proxy requests\n\
            # TYPE gh_proxy_fallback_requests counter\n\
            gh_proxy_fallback_requests {}\n\
            \n\
            # HELP gh_proxy_proxy_errors Proxy errors\n\
            # TYPE gh_proxy_proxy_errors counter\n\
            gh_proxy_proxy_errors {}\n\
            \n\
            # HELP gh_proxy_timeout_errors Timeout errors\n\
            # TYPE gh_proxy_timeout_errors counter\n\
            gh_proxy_timeout_errors {}\n\
            \n\
            # HELP gh_proxy_size_exceeded_errors Size exceeded errors\n\
            # TYPE gh_proxy_size_exceeded_errors counter\n\
            gh_proxy_size_exceeded_errors {}\n\
            \n\
            # HELP gh_proxy_access_denied_errors Access denied errors\n\
            # TYPE gh_proxy_access_denied_errors counter\n\
            gh_proxy_access_denied_errors {}\n",
            total,
            successful,
            failed,
            avg_duration,
            max_duration,
            bytes_received,
            bytes_sent,
            error_rate,
            github,
            fallback,
            proxy_err,
            timeout_err,
            size_err,
            access_err
        )
    }

    /// Get metrics as JSON
    pub fn as_json(&self) -> serde_json::Value {
        let total = self.total_requests.load(Ordering::Relaxed);
        let successful = self.successful_requests.load(Ordering::Relaxed);
        let failed = self.failed_requests.load(Ordering::Relaxed);

        serde_json::json!({
            "requests": {
                "total": total,
                "successful": successful,
                "failed": failed,
                "error_rate": if total > 0 { (failed as f64 / total as f64) * 100.0 } else { 0.0 }
            },
            "bytes": {
                "received": self.total_bytes_received.load(Ordering::Relaxed),
                "sent": self.total_bytes_sent.load(Ordering::Relaxed)
            },
            "duration_ms": {
                "average": if total > 0 { self.total_request_duration_ms.load(Ordering::Relaxed) / total } else { 0 },
                "max": self.max_request_duration_ms.load(Ordering::Relaxed)
            },
            "endpoints": {
                "github": self.github_requests.load(Ordering::Relaxed),
                "fallback": self.fallback_requests.load(Ordering::Relaxed)
            },
            "errors": {
                "proxy": self.proxy_errors.load(Ordering::Relaxed),
                "timeout": self.timeout_errors.load(Ordering::Relaxed),
                "size_exceeded": self.size_exceeded_errors.load(Ordering::Relaxed),
                "access_denied": self.access_denied_errors.load(Ordering::Relaxed)
            }
        })
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for tracking request metrics
pub struct RequestMetrics {
    start_time: Instant,
    collector: MetricsCollector,
}

impl RequestMetrics {
    /// Record successful request completion
    pub fn success(&self, bytes_sent: u64) {
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        self.collector
            .record_request_success(duration_ms, bytes_sent);
        debug!(
            "Request completed successfully: duration={}ms, bytes_sent={}",
            duration_ms, bytes_sent
        );
    }

    /// Record failed request completion
    pub fn error(&self) {
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        self.collector.record_request_error(duration_ms);
        debug!("Request failed: duration={}ms", duration_ms);
    }

    /// Get elapsed time since request start
    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let metrics = MetricsCollector::new();
        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.successful_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_recording() {
        let metrics = MetricsCollector::new();

        metrics.record_request_start();
        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 1);

        metrics.record_request_success(100, 1024);
        assert_eq!(metrics.successful_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_bytes_sent.load(Ordering::Relaxed), 1024);
    }

    #[test]
    fn test_metrics_error_tracking() {
        let metrics = MetricsCollector::new();

        metrics.record_proxy_error();
        metrics.record_timeout_error();
        metrics.record_access_denied_error();

        assert_eq!(metrics.proxy_errors.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.timeout_errors.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.access_denied_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_prometheus_format() {
        let metrics = MetricsCollector::new();
        metrics.total_requests.store(100, Ordering::Relaxed);
        metrics.successful_requests.store(95, Ordering::Relaxed);

        let prometheus = metrics.as_prometheus_metrics();
        assert!(prometheus.contains("gh_proxy_requests_total 100"));
        assert!(prometheus.contains("gh_proxy_requests_successful 95"));
        assert!(prometheus.contains("TYPE gh_proxy_requests_total counter"));
    }
}
