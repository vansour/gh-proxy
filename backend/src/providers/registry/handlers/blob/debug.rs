use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
};
use std::collections::HashMap;

fn required_param(params: &HashMap<String, String>, name: &str) -> Result<String, StatusCode> {
    params
        .get(name)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or(StatusCode::BAD_REQUEST)
}

pub async fn debug_blob_info(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    use serde_json::json;

    if !state.settings.debug.endpoints_enabled {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "Debug endpoints are disabled.\n",
        )
            .into_response();
    }

    let proxy = &state.docker_proxy;
    let name = match required_param(&params, "name") {
        Ok(value) => value,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "missing 'name' query parameter").into_response();
        }
    };
    let digest = match required_param(&params, "digest") {
        Ok(value) => value,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "missing 'digest' query parameter").into_response();
        }
    };
    let reference = params
        .get("reference")
        .cloned()
        .unwrap_or_else(|| "latest".to_string());

    match proxy.debug_blob_info(&name, &digest, &reference).await {
        Ok((manifest_size, actual_size)) => {
            let body = json!({"name": name, "reference": reference, "digest": digest, "manifest_size": manifest_size, "actual_blob_size": actual_size, "size_diff": (actual_size as i64 - manifest_size as i64)}).to_string();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!("debug_blob_info error: {}", error);
            (StatusCode::BAD_GATEWAY, format!("debug error: {}", error)).into_response()
        }
    }
}
