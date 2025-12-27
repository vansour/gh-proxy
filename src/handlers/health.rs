//! Health check handlers with detailed status information.

use crate::state::AppState;
use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};

/// Detailed health status response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Current server state
    pub state: String,
    /// Application version
    pub version: String,
    /// Number of active requests
    pub active_requests: usize,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Whether the server is accepting new requests
    pub accepting_requests: bool,
    /// Sub-system health checks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<HealthChecks>,
}

/// Individual health checks for sub-systems
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthChecks {
    /// Cloudflare integration status
    pub cloudflare: CheckStatus,
    /// Docker registry status
    pub registry: CheckStatus,
}

/// Status of an individual health check
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckStatus {
    /// Whether the check passed
    pub healthy: bool,
    /// Optional status message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Liveness probe endpoint
///
/// Returns basic health status for Kubernetes/container orchestration.
/// This endpoint is lightweight and does not perform external checks.
pub async fn health_liveness(State(state): State<AppState>) -> (StatusCode, Json<HealthStatus>) {
    let is_alive = state.shutdown_manager.is_alive().await;

    // Determine Cloudflare status
    let cf_status = CheckStatus {
        healthy: state.cloudflare_service.is_enabled(),
        message: if state.cloudflare_service.is_enabled() {
            Some("Enabled".to_string())
        } else {
            Some("Disabled (no credentials)".to_string())
        },
    };

    // Determine registry status
    let registry_status = CheckStatus {
        healthy: state.docker_proxy.is_some(),
        message: state
            .docker_proxy
            .as_ref()
            .map(|p| format!("Connected to {}", p.get_registry_url())),
    };

    let status = HealthStatus {
        state: format!("{:?}", state.shutdown_manager.get_state().await),
        version: env!("CARGO_PKG_VERSION").to_string(),
        active_requests: state.shutdown_manager.get_active_requests(),
        uptime_secs: state.uptime_tracker.uptime_secs(),
        accepting_requests: state.shutdown_manager.should_accept_request(),
        checks: Some(HealthChecks {
            cloudflare: cf_status,
            registry: registry_status,
        }),
    };

    let status_code = if is_alive {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(status))
}

/// Readiness probe endpoint (alias for liveness with same behavior)
///
/// Can be extended to perform more thorough checks if needed.
#[allow(dead_code)]
pub async fn health_readiness(State(state): State<AppState>) -> (StatusCode, Json<HealthStatus>) {
    health_liveness(State(state)).await
}
