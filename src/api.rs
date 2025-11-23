use crate::AppState;
use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use tracing::info;
// no docker preview API
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub server: ServerInfo,
    pub shell: ShellInfo,
    pub blacklist: BlacklistInfo,
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
pub async fn get_config(State(state): State<AppState>) -> Result<Json<ConfigResponse>, StatusCode> {
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
    };
    Ok(Json(config))
}

// docker preview API removed (frontend will not show preview)
