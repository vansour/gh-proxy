use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub server: ServerInfo,
    pub shell: ShellInfo,
    pub blacklist: BlacklistInfo,
    pub docker: DockerInfo,
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
pub struct BlacklistInfo {
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DockerInfo {
    pub enabled: bool,
}

/// GET /api/config - 获取配置信息
pub async fn get_config(
    State(state): State<AppState>,
) -> Result<Json<ConfigResponse>, StatusCode> {
    info!("API: Fetching configuration");
    
    let config = ConfigResponse {
        server: ServerInfo {
            size_limit: state.settings.server.size_limit,
        },
        shell: ShellInfo {
            editor: state.settings.shell.editor,
        },
        blacklist: BlacklistInfo {
            enabled: state.settings.blacklist.enabled,
        },
        docker: DockerInfo {
            enabled: state.settings.docker.enabled,
        },
    };
    
    Ok(Json(config))
}
