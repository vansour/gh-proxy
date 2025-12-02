use crate::AppState;
use crate::services::cloudflare::CloudflareStats;
use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub server: ServerInfo,
    pub shell: ShellInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    #[serde(rename = "sizeLimit")]
    pub size_limit: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShellInfo {
    pub editor: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    pub cloudflare: Option<CloudflareStats>,
}

pub async fn get_config(State(state): State<AppState>) -> Result<Json<ConfigResponse>, StatusCode> {
    let config = ConfigResponse {
        server: ServerInfo {
            size_limit: state.settings.server.size_limit,
        },
        shell: ShellInfo {
            editor: state.settings.shell.editor,
        },
    };
    Ok(Json(config))
}

pub async fn get_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let cf_stats = state.cloudflare_service.get_stats().await;
    let stats = StatsResponse {
        cloudflare: cf_stats,
    };
    Json(stats)
}
