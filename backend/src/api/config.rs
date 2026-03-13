use crate::state::AppState;
use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigResponse {
    pub server: ServerInfo,
    pub shell: ShellInfo,
    pub debug: DebugInfo,
    pub registry: RegistryInfo,
    pub proxy: ProxyInfo,
    pub cache: CacheInfo,
    pub rate_limit: RateLimitInfo,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub max_concurrent_requests: u32,
    pub request_timeout_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShellInfo {
    pub editor: bool,
    #[serde(rename = "publicBaseUrl")]
    pub public_base_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugInfo {
    pub endpoints_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryInfo {
    pub default: String,
    pub allowed_hosts: Vec<String>,
    pub readiness_depends_on_registry: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyInfo {
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheInfo {
    pub strategy: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitInfo {
    pub window_secs: u64,
    pub max_requests: u32,
}

pub async fn get_config(State(state): State<AppState>) -> Json<ConfigResponse> {
    Json(ConfigResponse {
        server: ServerInfo {
            max_concurrent_requests: state.settings.server.max_concurrent_requests,
            request_timeout_secs: state.settings.server.request_timeout_secs,
        },
        shell: ShellInfo {
            editor: state.settings.shell.editor,
            public_base_url: state.settings.shell.public_base_url.clone(),
        },
        debug: DebugInfo {
            endpoints_enabled: state.settings.debug.endpoints_enabled,
        },
        registry: RegistryInfo {
            default: state.settings.registry.default.clone(),
            allowed_hosts: state.settings.registry.allowed_hosts.clone(),
            readiness_depends_on_registry: state.settings.registry.readiness_depends_on_registry,
        },
        proxy: ProxyInfo {
            allowed_hosts: state.settings.proxy.allowed_hosts.clone(),
        },
        cache: CacheInfo {
            strategy: super::stats::cache_strategy_name(state.settings.cache.strategy).to_string(),
        },
        rate_limit: RateLimitInfo {
            window_secs: state.settings.rate_limit.window_secs,
            max_requests: state.settings.rate_limit.max_requests,
        },
    })
}
