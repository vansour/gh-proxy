/// Metrics exposition handlers for monitoring
/// Provides metrics in both Prometheus and JSON formats
use axum::{Json, extract::State, http::StatusCode};
use serde_json;

use crate::AppState;

/// GET /metrics - Prometheus metrics endpoint
/// Exposes metrics in Prometheus text format for scraping
pub async fn metrics_prometheus(State(state): State<AppState>) -> (StatusCode, String) {
    let prometheus_metrics = state.metrics.as_prometheus_metrics();
    (StatusCode::OK, prometheus_metrics)
}

/// GET /metrics/json - JSON metrics endpoint
/// Exposes metrics as JSON for programmatic access
pub async fn metrics_json(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(state.metrics.as_json())
}
