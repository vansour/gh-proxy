use crate::AppState;
use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use tracing::info;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_response_serialization() {
        let config = ConfigResponse {
            server: ServerInfo { size_limit: 100 },
            shell: ShellInfo { editor: true },
            blacklist: BlacklistInfo { enabled: false },
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("100"));
        assert!(json.contains("true"));
        assert!(json.contains("false"));
    }

    #[test]
    fn test_server_info_creation() {
        let server = ServerInfo { size_limit: 250 };
        assert_eq!(server.size_limit, 250);
    }

    #[test]
    fn test_shell_info_creation() {
        let shell = ShellInfo { editor: true };
        assert!(shell.editor);

        let shell_disabled = ShellInfo { editor: false };
        assert!(!shell_disabled.editor);
    }

    #[test]
    fn test_blacklist_info_creation() {
        let blacklist = BlacklistInfo { enabled: true };
        assert!(blacklist.enabled);

        let blacklist_disabled = BlacklistInfo { enabled: false };
        assert!(!blacklist_disabled.enabled);
    }
}
