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

    let status = HealthStatus {
        state: format!("{:?}", state.shutdown_manager.get_state().await),
        version: env!("CARGO_PKG_VERSION").to_string(),
        active_requests: state.shutdown_manager.get_active_requests(),
        uptime_secs: state.uptime_tracker.uptime_secs(),
        accepting_requests: state.shutdown_manager.should_accept_request(),
        checks: None,
    };

    let status_code = if is_alive {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(status))
}

/// Readiness probe endpoint.
///
/// By default readiness reflects only the local process state and whether the
/// server should accept new requests. The registry dependency is still probed
/// and reported in the JSON body, and can optionally participate in readiness
/// via `registry.readiness_depends_on_registry`.
pub async fn health_readiness(State(state): State<AppState>) -> (StatusCode, Json<HealthStatus>) {
    let healthy = state.docker_proxy.check_registry_health().await;
    let registry_status = CheckStatus {
        healthy,
        message: Some(format!(
            "{} ({})",
            state.docker_proxy.get_registry_url(),
            if healthy { "reachable" } else { "unreachable" }
        )),
    };

    let accepting_requests = state.shutdown_manager.should_accept_request();
    let registry_ready =
        !state.settings.registry.readiness_depends_on_registry || registry_status.healthy;
    let ready = state.shutdown_manager.is_ready().await && accepting_requests && registry_ready;
    let status = HealthStatus {
        state: format!("{:?}", state.shutdown_manager.get_state().await),
        version: env!("CARGO_PKG_VERSION").to_string(),
        active_requests: state.shutdown_manager.get_active_requests(),
        uptime_secs: state.uptime_tracker.uptime_secs(),
        accepting_requests,
        checks: Some(HealthChecks {
            registry: registry_status,
        }),
    };

    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(status),
    )
}
