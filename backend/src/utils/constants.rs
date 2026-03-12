//! Global constants definition

use std::time::Duration;

/// Maximum memory buffer size (256KB)
pub const MAX_MEMORY_BUFFER_SIZE: u64 = 256 * 1024;

/// Maximum redirect count
pub const MAX_REDIRECTS: u32 = 10;

/// Slow request threshold (seconds)
pub const SLOW_REQUEST_THRESHOLD: Duration = Duration::from_secs(5);

/// Cache constants
pub mod cache {
    use super::*;

    /// Default TTL for metrics cache
    pub const METRICS_CACHE_TTL: Duration = Duration::from_secs(5);

    /// Request duration buckets
    pub const REQUEST_DURATION_BUCKETS: &[f64] = &[
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];
}

/// HTTP related constants
pub mod http {
    /// Connection timeout (seconds)
    pub const CONNECT_TIMEOUT_SECS: u64 = 10;
}
