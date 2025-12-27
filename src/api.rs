//! API endpoints for configuration and statistics.

use crate::infra::metrics;
use crate::services::cloudflare::CloudflareStats;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};

// ============================================================================
// Configuration API
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub server: ServerInfo,
    pub shell: ShellInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    #[serde(rename = "sizeLimit")]
    pub size_limit: u64,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u32,
    #[serde(rename = "requestTimeoutSecs")]
    pub request_timeout_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShellInfo {
    pub editor: bool,
}

/// Get current server configuration (public subset)
pub async fn get_config(State(state): State<AppState>) -> Result<Json<ConfigResponse>, StatusCode> {
    let config = ConfigResponse {
        server: ServerInfo {
            size_limit: state.settings.server.size_limit,
            max_concurrent_requests: state.settings.server.max_concurrent_requests,
            request_timeout_secs: state.settings.server.request_timeout_secs,
        },
        shell: ShellInfo {
            editor: state.settings.shell.editor,
        },
    };
    Ok(Json(config))
}

// ============================================================================
// Statistics API
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Cloudflare CDN statistics (if enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudflare: Option<CloudflareStats>,
    /// Server-side metrics
    pub server: ServerStats,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerStats {
    /// Total requests processed
    pub total_requests: u64,
    /// Currently active requests
    pub active_requests: i64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Rate limiter cache size
    pub rate_limit_cache_size: u64,
}

/// Get server and CDN statistics
pub async fn get_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let cf_stats = state.cloudflare_service.get_stats().await;

    let server_stats = ServerStats {
        total_requests: metrics::HTTP_REQUESTS_TOTAL.get(),
        active_requests: metrics::HTTP_ACTIVE_REQUESTS.get(),
        bytes_transferred: metrics::BYTES_TRANSFERRED_TOTAL.get(),
        uptime_secs: state.uptime_tracker.uptime_secs(),
        rate_limit_cache_size: state.rate_limiter.cache_size(),
    };

    let stats = StatsResponse {
        cloudflare: cf_stats,
        server: server_stats,
    };

    Json(stats)
}
