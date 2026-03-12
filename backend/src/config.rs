use crate::cache::config as cache_config;
use crate::services::request::normalize_public_base_url;
use http::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use std::{collections::HashSet, fs, path::PathBuf};
use thiserror::Error;

const CONTAINER_CONFIG_PATH: &str = "/app/config/config.toml";
const LOCAL_CONFIG_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/config/config.toml");
const DEFAULT_ORIGIN_AUTH_HEADER_NAME: &str = "x-gh-proxy-origin-auth";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file at {path}: {source}")]
    Io {
        source: std::io::Error,
        path: String,
    },
    #[error("failed to parse config: {0}")]
    Parse(toml::de::Error),
    #[error("configuration validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Settings {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub shell: ShellConfig,
    #[serde(default)]
    pub ingress: IngressConfig,
    #[serde(default)]
    pub debug: DebugConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub registry: RegistryConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub cache: cache_config::CacheConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

impl Settings {
    pub fn load() -> Result<Self, ConfigError> {
        let config_path = std::env::var("GH_PROXY_CONFIG")
            .unwrap_or_else(|_| default_config_path().to_string_lossy().to_string());
        let raw = fs::read_to_string(&config_path).map_err(|source| ConfigError::Io {
            source,
            path: config_path.clone(),
        })?;
        let mut settings: Settings = toml::from_str(&raw).map_err(ConfigError::Parse)?;
        settings.validate()?;
        Ok(settings)
    }
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        self.server.finalize();
        self.server.validate()?;
        self.shell.validate()?;
        self.ingress.validate()?;
        self.debug.validate()?;
        self.log.validate()?;
        self.registry.validate()?;
        self.proxy.validate()?;
        self.cache
            .validate()
            .map_err(|e| ConfigError::Validation(format!("cache: {}", e)))?;
        self.rate_limit
            .validate()
            .map_err(|e| ConfigError::Validation(format!("rate_limit: {}", e)))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    #[serde(alias = "allowedHosts")]
    pub allowed_hosts: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: vec![
                "github.com".to_string(),
                "*.github.com".to_string(),
                "githubusercontent.com".to_string(),
                "*.githubusercontent.com".to_string(),
            ],
        }
    }
}

impl ProxyConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        self.allowed_hosts =
            normalize_host_pattern_list(&self.allowed_hosts, "proxy.allowed_hosts")?;
        Ok(())
    }
    pub(crate) fn host_patterns(&self) -> Vec<HostPattern> {
        self.allowed_hosts
            .iter()
            .map(|pattern| HostPattern::parse(pattern).expect("validated pattern became invalid"))
            .collect()
    }
}

fn normalize_host_pattern_list(
    entries: &[String],
    field_name: &str,
) -> Result<Vec<String>, ConfigError> {
    let mut normalized = Vec::with_capacity(entries.len());
    let mut seen = HashSet::with_capacity(entries.len());
    for entry in entries {
        let pattern = entry.trim();
        if pattern.is_empty() {
            continue;
        }
        let parsed = HostPattern::parse(pattern).map_err(|err| {
            ConfigError::Validation(format!(
                "{} entry '{}' is invalid: {}",
                field_name, entry, err
            ))
        })?;
        let canonical = parsed.canonical_pattern();
        if seen.insert(canonical.clone()) {
            normalized.push(canonical);
        }
    }
    Ok(normalized)
}

fn format_host_authority(host: &str, port: Option<u16>) -> String {
    let host = if host.contains(':') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };

    match port {
        Some(port) => format!("{}:{}", host, port),
        None => host,
    }
}

fn normalize_registry_default(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("value cannot be empty".to_string());
    }

    let host_pattern = HostPattern::parse(value)?;
    if host_pattern.kind != HostPatternKind::Exact {
        return Err("wildcards are not allowed".to_string());
    }

    let has_scheme = value.contains("://");
    let parse_target = if has_scheme {
        value.to_string()
    } else {
        format!("https://{}", value)
    };

    let uri: http::Uri = parse_target
        .parse()
        .map_err(|err| format!("must be a host or absolute http(s) URL: {}", err))?;
    let host = uri
        .host()
        .ok_or_else(|| "host is required".to_string())?
        .to_ascii_lowercase();
    let authority = format_host_authority(&host, uri.port_u16());

    if has_scheme {
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| "scheme is required".to_string())?;
        if !matches!(scheme, "http" | "https") {
            return Err("scheme must be http or https".to_string());
        }
        Ok(format!("{}://{}", scheme.to_ascii_lowercase(), authority))
    } else {
        Ok(authority)
    }
}

#[derive(Debug, Clone)]
pub struct HostPattern {
    value: String,
    kind: HostPatternKind,
    suffix: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostPatternKind {
    Exact,
    Suffix,
}

impl HostPattern {
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        let mut pattern = raw.trim();
        if pattern.is_empty() {
            return Err("value cannot be empty".to_string());
        }
        if let Some(idx) = pattern.find("://") {
            pattern = &pattern[idx + 3..];
        }
        if let Some((host_part, _)) = pattern.split_once('/') {
            pattern = host_part;
        }
        if pattern.starts_with('[') {
            let closing = pattern
                .find(']')
                .ok_or_else(|| "missing closing ']' for IPv6 literal".to_string())?;
            pattern = &pattern[1..closing];
        } else if let Some((host, _)) = pattern.split_once(':') {
            pattern = host;
        }
        pattern = pattern.trim();
        let (kind, host) = if let Some(stripped) = pattern.strip_prefix("*.") {
            (HostPatternKind::Suffix, stripped)
        } else if let Some(stripped) = pattern.strip_prefix('.') {
            (HostPatternKind::Suffix, stripped)
        } else {
            (HostPatternKind::Exact, pattern)
        };
        let host = host.trim_matches('.');
        if host.is_empty() {
            return Err("resolved host is empty".to_string());
        }
        if host.contains('*') {
            return Err("wildcards must use to '*.example.com' form".to_string());
        }
        let value = host.to_ascii_lowercase();
        let suffix = match kind {
            HostPatternKind::Exact => None,
            HostPatternKind::Suffix => Some(format!(".{}", value)),
        };
        Ok(Self {
            value,
            kind,
            suffix,
        })
    }

    fn canonical_pattern(&self) -> String {
        match self.kind {
            HostPatternKind::Exact => self.value.clone(),
            HostPatternKind::Suffix => format!("*.{}", self.value),
        }
    }

    pub(crate) fn matches(&self, host: &str) -> bool {
        match self.kind {
            HostPatternKind::Exact => host == self.value,
            HostPatternKind::Suffix => {
                host == self.value
                    || self
                        .suffix
                        .as_ref()
                        .map(|suffix| host.ends_with(suffix))
                        .unwrap_or(false)
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PoolConfig {
    #[serde(default = "default_idle_timeout", alias = "idleTimeoutSecs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_max_idle", alias = "maxIdlePerHost")]
    pub max_idle_per_host: usize,
    #[serde(default = "default_stream_window", alias = "http2StreamWindowSize")]
    pub http2_stream_window_size: u32,
    #[serde(
        default = "default_connection_window",
        alias = "http2ConnectionWindowSize"
    )]
    pub http2_connection_window_size: u32,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: default_idle_timeout(),
            max_idle_per_host: default_max_idle(),
            http2_stream_window_size: default_stream_window(),
            http2_connection_window_size: default_connection_window(),
        }
    }
}

impl PoolConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.idle_timeout_secs == 0 {
            return Err(ConfigError::Validation(
                "server.pool.idle_timeout_secs must be positive".to_string(),
            ));
        }
        if self.max_idle_per_host == 0 {
            return Err(ConfigError::Validation(
                "server.pool.max_idle_per_host must be positive".to_string(),
            ));
        }
        if self.http2_stream_window_size == 0 {
            return Err(ConfigError::Validation(
                "server.pool.http2_stream_window_size must be positive".to_string(),
            ));
        }
        if self.http2_connection_window_size == 0 {
            return Err(ConfigError::Validation(
                "server.pool.http2_connection_window_size must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

fn default_idle_timeout() -> u64 {
    90
}
fn default_max_idle() -> usize {
    32
}
fn default_stream_window() -> u32 {
    2 * 1024 * 1024
}
fn default_connection_window() -> u32 {
    8 * 1024 * 1024
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(alias = "sizeLimit")]
    pub size_limit: u64,
    #[serde(alias = "requestTimeoutSecs")]
    pub request_timeout_secs: u64,
    #[serde(alias = "maxConcurrentRequests")]
    pub max_concurrent_requests: u32,
    #[serde(alias = "requestSizeLimit")]
    pub request_size_limit: u64,
    #[serde(default)]
    pub pool: PoolConfig,
}

impl ServerConfig {
    fn finalize(&mut self) {
        if self.host.is_empty() {
            self.host = "0.0.0.0".to_string();
        }
        if self.port == 0 {
            self.port = 8080;
        }
    }
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.size_limit == 0 {
            return Err(ConfigError::Validation(
                "server.size_limit must be at least 1 MB".to_string(),
            ));
        }
        if self.request_timeout_secs == 0 {
            return Err(ConfigError::Validation(
                "server.request_timeout_secs must be positive".to_string(),
            ));
        }
        if self.max_concurrent_requests == 0 {
            return Err(ConfigError::Validation(
                "server.max_concurrent_requests must be positive".to_string(),
            ));
        }
        if self.request_size_limit == 0 {
            return Err(ConfigError::Validation(
                "server.request_size_limit must be positive".to_string(),
            ));
        }
        self.pool.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ShellConfig {
    pub editor: bool,
    #[serde(alias = "publicBaseUrl")]
    pub public_base_url: String,
}

impl ShellConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let trimmed = self.public_base_url.trim();
        if trimmed.is_empty() {
            self.public_base_url.clear();
            return Ok(());
        }

        self.public_base_url = normalize_public_base_url(trimmed).map_err(|err| {
            ConfigError::Validation(format!("shell.public_base_url is invalid: {}", err))
        })?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IngressConfig {
    #[serde(alias = "authHeaderName")]
    pub auth_header_name: String,
    #[serde(alias = "authHeaderValue")]
    pub auth_header_value: String,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            auth_header_name: DEFAULT_ORIGIN_AUTH_HEADER_NAME.to_string(),
            auth_header_value: String::new(),
        }
    }
}

impl IngressConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let header_name = self.auth_header_name.trim();
        let header_name = if header_name.is_empty() {
            DEFAULT_ORIGIN_AUTH_HEADER_NAME
        } else {
            header_name
        };
        let normalized = HeaderName::from_bytes(header_name.as_bytes()).map_err(|_| {
            ConfigError::Validation(format!(
                "ingress.auth_header_name '{}' is not a valid HTTP header name",
                self.auth_header_name
            ))
        })?;

        self.auth_header_name = normalized.as_str().to_string();
        self.auth_header_value = self.auth_header_value.trim().to_string();
        Ok(())
    }

    pub fn auth_header_enabled(&self) -> bool {
        !self.auth_header_value.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct DebugConfig {
    #[serde(alias = "endpointsEnabled")]
    pub endpoints_enabled: bool,
    #[serde(alias = "metricsEnabled")]
    pub metrics_enabled: bool,
}

impl DebugConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

impl LogConfig {
    pub fn get_level(&self) -> &str {
        &self.level
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self.level.to_lowercase().as_str() {
            "debug" | "info" | "warn" | "error" | "trace" | "none" => {}
            _ => {
                return Err(ConfigError::Validation(format!(
                    "Invalid log level '{}'",
                    self.level
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AuthConfig {
    pub token: String,
}

impl AuthConfig {
    pub fn authorization_header(
        &self,
    ) -> Result<Option<HeaderValue>, http::header::InvalidHeaderValue> {
        let token = self.token.trim();
        if token.is_empty() {
            return Ok(None);
        }
        let mut value = String::with_capacity(token.len() + 6);
        value.push_str("token ");
        value.push_str(token);
        HeaderValue::from_str(&value).map(Some)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RegistryConfig {
    #[serde(alias = "defaultRegistry")]
    pub default: String,
    #[serde(alias = "allowedHosts")]
    pub allowed_hosts: Vec<String>,
    #[serde(alias = "readinessDependsOnRegistry")]
    pub readiness_depends_on_registry: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            default: "registry-1.docker.io".to_string(),
            allowed_hosts: vec!["registry-1.docker.io".to_string()],
            readiness_depends_on_registry: false,
        }
    }
}

impl RegistryConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        if self.default.trim().is_empty() {
            return Err(ConfigError::Validation(
                "registry.default must not be empty".to_string(),
            ));
        }

        self.default = normalize_registry_default(&self.default).map_err(|err| {
            ConfigError::Validation(format!("registry.default is invalid: {}", err))
        })?;

        let default_host = HostPattern::parse(&self.default)
            .map_err(|err| {
                ConfigError::Validation(format!("registry.default is invalid: {}", err))
            })?
            .value;

        let mut normalized =
            normalize_host_pattern_list(&self.allowed_hosts, "registry.allowed_hosts")?;
        if !normalized.iter().any(|entry| entry == &default_host) {
            normalized.push(default_host);
        }
        self.allowed_hosts = normalized;

        Ok(())
    }

    pub(crate) fn host_patterns(&self) -> Vec<HostPattern> {
        self.allowed_hosts
            .iter()
            .map(|pattern| HostPattern::parse(pattern).expect("validated pattern became invalid"))
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    #[serde(default = "default_window", alias = "windowSecs")]
    pub window_secs: u64,
    #[serde(default = "default_max_requests", alias = "maxRequests")]
    pub max_requests: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window_secs: default_window(),
            max_requests: default_max_requests(),
        }
    }
}

fn default_window() -> u64 {
    60
}
fn default_max_requests() -> u32 {
    100
}

impl RateLimitConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.window_secs == 0 {
            return Err(ConfigError::Validation(
                "rate_limit.window_secs must be positive".to_string(),
            ));
        }
        if self.max_requests == 0 {
            return Err(ConfigError::Validation(
                "rate_limit.max_requests must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

pub struct GitHubConfig {
    pub default_host: String,
    allowed_hosts: Vec<HostPattern>,
}

impl GitHubConfig {
    pub fn new(_auth_token: &str, proxy: &ProxyConfig) -> Self {
        Self {
            default_host: "github.com".to_string(),
            allowed_hosts: proxy.host_patterns(),
        }
    }
    pub fn is_allowed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.allowed_hosts
            .iter()
            .any(|pattern| pattern.matches(&host))
    }
}

pub fn default_config_path() -> PathBuf {
    [CONTAINER_CONFIG_PATH, LOCAL_CONFIG_PATH]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .unwrap_or_else(|| PathBuf::from(CONTAINER_CONFIG_PATH))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_validate_rejects_zero_runtime_limits() {
        let config = ServerConfig {
            size_limit: 64,
            request_timeout_secs: 0,
            max_concurrent_requests: 16,
            request_size_limit: 8,
            ..ServerConfig::default()
        };

        let error = config.validate().expect_err("zero timeout should fail");
        assert!(error.to_string().contains("server.request_timeout_secs"));
    }

    #[test]
    fn registry_validate_rejects_empty_default() {
        let mut config = RegistryConfig {
            default: "   ".to_string(),
            ..RegistryConfig::default()
        };

        let error = config
            .validate()
            .expect_err("empty registry default should fail");
        assert!(error.to_string().contains("registry.default"));
    }

    #[test]
    fn registry_validate_adds_default_host_to_allowed_hosts() {
        let mut config = RegistryConfig {
            default: "https://ghcr.io".to_string(),
            allowed_hosts: vec![],
            readiness_depends_on_registry: false,
        };

        config.validate().expect("registry config should validate");

        assert!(config.allowed_hosts.iter().any(|host| host == "ghcr.io"));
    }

    #[test]
    fn proxy_validate_normalizes_and_deduplicates_allowed_hosts() {
        let mut config = ProxyConfig {
            allowed_hosts: vec![
                " HTTPS://GitHub.COM/owner/repo ".to_string(),
                "github.com".to_string(),
                ".GitHubUserContent.com".to_string(),
                "*.githubusercontent.com".to_string(),
                "   ".to_string(),
            ],
        };

        config.validate().expect("proxy config should validate");

        assert_eq!(
            config.allowed_hosts,
            vec![
                "github.com".to_string(),
                "*.githubusercontent.com".to_string()
            ]
        );
    }

    #[test]
    fn registry_validate_normalizes_default_origin_and_deduplicates_allowed_hosts() {
        let mut config = RegistryConfig {
            default: " HTTPS://GHCR.IO/v2/ ".to_string(),
            allowed_hosts: vec![
                "ghcr.io".to_string(),
                "https://ghcr.io/token".to_string(),
                ".Example.com".to_string(),
                "*.example.com".to_string(),
            ],
            readiness_depends_on_registry: false,
        };

        config.validate().expect("registry config should validate");

        assert_eq!(config.default, "https://ghcr.io".to_string());
        assert_eq!(
            config.allowed_hosts,
            vec!["ghcr.io".to_string(), "*.example.com".to_string()]
        );
    }

    #[test]
    fn registry_validate_rejects_wildcard_default() {
        let mut config = RegistryConfig {
            default: "*.example.com".to_string(),
            ..RegistryConfig::default()
        };

        let error = config.validate().expect_err("wildcard default should fail");
        assert!(error.to_string().contains("registry.default"));
        assert!(error.to_string().contains("wildcards"));
    }

    #[test]
    fn settings_support_legacy_aliases() {
        let mut settings: Settings = toml::from_str(
            r#"
[server]
sizeLimit = 64
requestTimeoutSecs = 12
maxConcurrentRequests = 20
requestSizeLimit = 8

[server.pool]
idleTimeoutSecs = 30
maxIdlePerHost = 16
http2StreamWindowSize = 1048576
http2ConnectionWindowSize = 4194304

[registry]
defaultRegistry = "registry-1.docker.io"
allowedHosts = ["ghcr.io"]
readinessDependsOnRegistry = true

[ingress]
authHeaderName = "x-origin-auth"
authHeaderValue = "secret"

[debug]
endpointsEnabled = true
metricsEnabled = true

[rate_limit]
windowSecs = 30
maxRequests = 50
"#,
        )
        .expect("legacy aliases should deserialize");

        settings.validate().expect("settings should validate");
        assert_eq!(settings.server.size_limit, 64);
        assert_eq!(settings.server.request_timeout_secs, 12);
        assert_eq!(settings.server.max_concurrent_requests, 20);
        assert_eq!(settings.server.request_size_limit, 8);
        assert_eq!(settings.server.pool.idle_timeout_secs, 30);
        assert_eq!(settings.server.pool.max_idle_per_host, 16);
        assert_eq!(settings.server.pool.http2_stream_window_size, 1_048_576);
        assert_eq!(settings.server.pool.http2_connection_window_size, 4_194_304);
        assert_eq!(settings.registry.default, "registry-1.docker.io");
        assert_eq!(
            settings.registry.allowed_hosts,
            vec!["ghcr.io".to_string(), "registry-1.docker.io".to_string()]
        );
        assert!(settings.registry.readiness_depends_on_registry);
        assert_eq!(settings.ingress.auth_header_name, "x-origin-auth");
        assert_eq!(settings.ingress.auth_header_value, "secret");
        assert!(settings.debug.endpoints_enabled);
        assert!(settings.debug.metrics_enabled);
        assert_eq!(settings.rate_limit.window_secs, 30);
        assert_eq!(settings.rate_limit.max_requests, 50);
    }

    #[test]
    fn ingress_validate_rejects_invalid_header_name() {
        let mut ingress = IngressConfig {
            auth_header_name: "bad header".to_string(),
            auth_header_value: "secret".to_string(),
        };

        let error = ingress
            .validate()
            .expect_err("invalid ingress header name should fail");
        assert!(error.to_string().contains("ingress.auth_header_name"));
    }
}
