use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, Response};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerStats {
    pub total_requests: u64,
    pub active_requests: i64,
    pub bytes_transferred: u64,
    pub uptime_secs: u64,
    pub rate_limit_cache_size: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheStats {
    pub strategy: String,
    pub entry_count: u64,
    pub weighted_size: u64,
    pub hit_rate: f64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestStats {
    pub by_status: BTreeMap<String, u64>,
    pub by_type: BTreeMap<String, u64>,
    pub by_method: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatsResponse {
    pub server: ServerStats,
    pub cache: CacheStats,
    pub requests: RequestStats,
    pub errors: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthStatus {
    pub state: String,
    pub version: String,
    pub active_requests: usize,
    pub uptime_secs: u64,
    pub accepting_requests: bool,
    pub checks: Option<HealthChecks>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthChecks {
    pub registry: CheckStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckStatus {
    pub healthy: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigResponse {
    pub server: ServerConfigInfo,
    pub shell: ShellConfigInfo,
    pub debug: DebugConfigInfo,
    pub registry: RegistryConfigInfo,
    pub proxy: ProxyConfigInfo,
    pub cache: CacheConfigInfo,
    #[serde(rename = "rateLimit")]
    pub rate_limit: RateLimitConfigInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfigInfo {
    pub max_concurrent_requests: u32,
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShellConfigInfo {
    pub editor: bool,
    #[serde(rename = "publicBaseUrl")]
    pub public_base_url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugConfigInfo {
    pub endpoints_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryConfigInfo {
    pub default: String,
    pub allowed_hosts: Vec<String>,
    pub readiness_depends_on_registry: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConfigInfo {
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheConfigInfo {
    pub strategy: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitConfigInfo {
    pub window_secs: u64,
    pub max_requests: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DashboardData {
    pub stats: Option<StatsResponse>,
    pub stats_error: Option<String>,
    pub health: Option<HealthStatus>,
    pub readyz_status: Option<u16>,
    pub health_error: Option<String>,
    pub config: Option<ConfigResponse>,
    pub config_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct HealthSnapshot {
    status_code: u16,
    body: HealthStatus,
}

async fn fetch_json_with_status<T>(url: &str) -> Result<(u16, T), String>
where
    T: for<'de> Deserialize<'de>,
{
    let opts = RequestInit::new();
    opts.set_method("GET");

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| format!("Failed to create request: {:?}", e))?;

    let window = web_sys::window().ok_or_else(|| "window is unavailable".to_string())?;
    let response_promise = window.fetch_with_request(&request);
    let response_value = JsFuture::from(response_promise)
        .await
        .map_err(|e| format!("Fetch failed: {:?}", e))?;

    let response: Response = response_value
        .dyn_into()
        .map_err(|e| format!("Response conversion failed: {:?}", e))?;
    let status = response.status();

    let json_result = response.json();
    let json_promise = match json_result {
        Ok(p) => p,
        Err(e) => return Err(format!("JSON() failed: {:?}", e)),
    };

    let json_value = JsFuture::from(json_promise)
        .await
        .map_err(|e| format!("JSON parse failed: {:?}", e))?;

    let parsed = serde_wasm_bindgen::from_value::<T>(json_value)
        .map_err(|e| format!("Deserialization failed: {:?}", e))?;

    Ok((status, parsed))
}

async fn fetch_json<T>(url: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let (status, body) = fetch_json_with_status(url).await?;
    if !(200..300).contains(&status) {
        return Err(format!("Request failed with status: {}", status));
    }
    Ok(body)
}

pub async fn fetch_stats() -> Result<StatsResponse, String> {
    fetch_json("/api/stats").await
}

async fn fetch_health_snapshot() -> Result<HealthSnapshot, String> {
    let (status_code, body) = fetch_json_with_status("/readyz").await?;
    Ok(HealthSnapshot { status_code, body })
}

pub async fn fetch_config() -> Result<ConfigResponse, String> {
    fetch_json("/api/config").await
}

pub async fn fetch_dashboard() -> DashboardData {
    let stats = fetch_stats().await;
    let health = fetch_health_snapshot().await;
    let config = fetch_config().await;

    let (stats, stats_error) = match stats {
        Ok(stats) => (Some(stats), None),
        Err(error) => (None, Some(error)),
    };
    let (health, readyz_status, health_error) = match health {
        Ok(snapshot) => (Some(snapshot.body), Some(snapshot.status_code), None),
        Err(error) => (None, None, Some(error)),
    };
    let (config, config_error) = match config {
        Ok(config) => (Some(config), None),
        Err(error) => (None, Some(error)),
    };

    DashboardData {
        stats,
        stats_error,
        health,
        readyz_status,
        health_error,
        config,
        config_error,
    }
}
