//! Application state and shared types.

use crate::config::{GitHubConfig, Settings};
use crate::services::{
    cloudflare::CloudflareService, ipinfo::IpInfoService, shutdown::ShutdownManager,
    shutdown::UptimeTracker,
};
use axum::body::Body;
use http::header::HeaderValue;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Application state shared across all request handlers.
#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub github_config: Arc<GitHubConfig>,
    pub client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
    pub shutdown_manager: ShutdownManager,
    pub uptime_tracker: Arc<UptimeTracker>,
    pub auth_header: Option<HeaderValue>,
    pub docker_proxy: Option<Arc<crate::providers::registry::DockerProxy>>,
    pub download_semaphore: Arc<Semaphore>,
    pub cloudflare_service: Arc<CloudflareService>,
    pub ip_info_service: Arc<IpInfoService>,
}

/// Post-processor for response body transformation.
#[derive(Clone)]
pub enum ResponsePostProcessor {
    /// Shell editor mode: inject proxy URL into GitHub URLs.
    ShellEditor { proxy_url: Arc<str> },
}
