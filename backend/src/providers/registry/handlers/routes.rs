use super::super::path::{V2Endpoint, parse_v2_path};
use super::blob::{get_blob, head_blob, initiate_blob_upload};
use super::manifest::{get_manifest, head_manifest};
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

pub async fn handle_v2_check() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    if let Ok(value) = "registry/2.0".parse() {
        headers.insert("Docker-Distribution-Api-Version", value);
    }
    (StatusCode::OK, headers)
}

pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    use serde_json::json;

    let version = env!("CARGO_PKG_VERSION");
    let registry = state.docker_proxy.get_registry_url().to_string();
    let healthy = state.docker_proxy.check_registry_health().await;
    let status = if healthy { "healthy" } else { "degraded" };
    let http_status = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs();
    let resp = json!({"status": status, "version": version, "registry": {"url": registry, "healthy": healthy}, "timestamp": ts}).to_string();
    (
        http_status,
        [(header::CONTENT_TYPE, "application/json")],
        resp,
    )
}

fn read_only_registry_response() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "Read-only registry proxy: push is not supported",
    )
        .into_response()
}

pub async fn v2_get(State(state): State<AppState>, Path(rest): Path<String>) -> Response {
    match parse_v2_path(&rest) {
        V2Endpoint::Manifest { name, reference } => {
            get_manifest(State(state), Path((name, reference))).await
        }
        V2Endpoint::Blob { name, digest } => get_blob(State(state), Path((name, digest)))
            .await
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn v2_head(State(state): State<AppState>, Path(rest): Path<String>) -> Response {
    match parse_v2_path(&rest) {
        V2Endpoint::Manifest { name, reference } => {
            head_manifest(State(state), Path((name, reference))).await
        }
        V2Endpoint::Blob { name, digest } => head_blob(State(state), Path((name, digest)))
            .await
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn v2_post(State(state): State<AppState>, Path(rest): Path<String>) -> Response {
    match parse_v2_path(&rest) {
        V2Endpoint::BlobUploadInit { name } => initiate_blob_upload(State(state), Path(name)).await,
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn v2_put(State(_state): State<AppState>, Path(rest): Path<String>) -> Response {
    match parse_v2_path(&rest) {
        V2Endpoint::BlobUploadComplete { .. } => read_only_registry_response(),
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn v2_patch(State(_state): State<AppState>, Path(rest): Path<String>) -> Response {
    match parse_v2_path(&rest) {
        V2Endpoint::BlobUploadInit { .. } | V2Endpoint::BlobUploadComplete { .. } => {
            read_only_registry_response()
        }
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}
