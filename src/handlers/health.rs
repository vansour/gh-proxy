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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_creation() {
        let status = HealthStatus {
            state: "Running".to_string(),
            version: "1.0.0".to_string(),
            active_requests: 5,
            uptime_secs: 3600,
            accepting_requests: true,
        };

        assert_eq!(status.state, "Running");
        assert_eq!(status.version, "1.0.0");
        assert_eq!(status.active_requests, 5);
        assert_eq!(status.uptime_secs, 3600);
        assert!(status.accepting_requests);
    }

    #[test]
    fn test_health_status_serialization() {
        let status = HealthStatus {
            state: "Running".to_string(),
            version: "1.0.4".to_string(),
            active_requests: 0,
            uptime_secs: 7200,
            accepting_requests: true,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"state\":\"Running\""));
        assert!(json.contains("\"version\":\"1.0.4\""));
        assert!(json.contains("\"active_requests\":0"));
        assert!(json.contains("\"uptime_secs\":7200"));
        assert!(json.contains("\"accepting_requests\":true"));
    }

    #[test]
    fn test_health_status_not_accepting_requests() {
        let status = HealthStatus {
            state: "Shutting Down".to_string(),
            version: "1.0.0".to_string(),
            active_requests: 10,
            uptime_secs: 5000,
            accepting_requests: false,
        };

        assert!(!status.accepting_requests);
    }
}
