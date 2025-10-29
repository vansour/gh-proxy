use crate::AppState;
use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    pub state: String,
    pub version: String,
    pub active_requests: usize,
    pub uptime_secs: u64,
    pub accepting_requests: bool,
}
pub async fn health_liveness(State(state): State<AppState>) -> (StatusCode, Json<HealthStatus>) {
    let is_alive = state.shutdown_manager.is_alive().await;
    let status = HealthStatus {
        state: format!("{:?}", state.shutdown_manager.get_state().await),
        version: env!("CARGO_PKG_VERSION").to_string(),
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
