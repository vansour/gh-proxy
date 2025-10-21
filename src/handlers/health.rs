/// Health check handlers for Kubernetes and monitoring
/// Provides liveness and readiness probes for container orchestration

use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    pub state: String,
    pub active_requests: usize,
    pub uptime_secs: u64,
    pub accepting_requests: bool,
}

/// GET /healthz - Liveness probe (is server alive)
/// Returns OK if the server process is running, regardless of readiness
pub async fn health_liveness(
    State(state): State<AppState>,
) -> (StatusCode, Json<HealthStatus>) {
    let is_alive = state.shutdown_manager.is_alive().await;
    let status = HealthStatus {
        state: format!("{:?}", state.shutdown_manager.get_state().await),
        active_requests: state.shutdown_manager.get_active_requests(),
        uptime_secs: state.uptime_tracker.uptime_secs(),
        accepting_requests: state.shutdown_manager.should_accept_request(),
    };

    let status_code = if is_alive {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(status))
}

/// GET /readyz - Readiness probe (is server ready)
/// Returns OK only when the server is fully initialized and ready to serve requests
pub async fn health_readiness(
    State(state): State<AppState>,
) -> (StatusCode, Json<HealthStatus>) {
    let is_ready = state.shutdown_manager.is_ready().await;
    let status = HealthStatus {
        state: format!("{:?}", state.shutdown_manager.get_state().await),
        active_requests: state.shutdown_manager.get_active_requests(),
        uptime_secs: state.uptime_tracker.uptime_secs(),
        accepting_requests: state.shutdown_manager.should_accept_request(),
    };

    let status_code = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(status))
}
