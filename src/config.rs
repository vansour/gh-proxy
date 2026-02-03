use http::header::HeaderValue;
use serde::Deserialize;
use std::{fs, path::Path};
use thiserror::Error;

const DEFAULT_CONFIG_PATH: &str = "/app/config/config.toml";

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

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub shell: ShellConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub registry: RegistryConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
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
        self.log.validate()?;
        self.proxy.validate()?;
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
        let mut normalized = Vec::with_capacity(self.allowed_hosts.len());
        for entry in self.allowed_hosts.iter() {
            let pattern = entry.trim();
            if pattern.is_empty() {
                continue;
            }
            HostPattern::parse(pattern).map_err(|err| {
                ConfigError::Validation(format!(
                    "proxy.allowedHosts entry '{}' is invalid: {}",
                    entry, err
                ))
            })?;
            normalized.push(pattern.to_ascii_lowercase());
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
    fn parse(raw: &str) -> Result<Self, String> {
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
            return Err("wildcards must use the '*.example.com' form".to_string());
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
    fn matches(&self, host: &str) -> bool {
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

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct RetryConfig {
    #[serde(alias = "maxAttempts")]
    pub max_attempts: u32,
    #[serde(alias = "baseDelayMs")]
    pub base_delay_ms: u64,
    #[serde(alias = "maxDelayMs")]
    pub max_delay_ms: u64,
}

impl RetryConfig {
    pub fn should_retry(&self, attempt: u32, error: &crate::errors::ProxyError) -> bool {
        if attempt >= self.max_attempts {
            return false;
        }
        match error {
            crate::errors::ProxyError::Http(_) => true,
            crate::errors::ProxyError::ProcessingError(msg) if msg.contains("timeout") => true,
            _ => false,
        }
    }

    pub fn get_delay(&self, attempt: u32) -> std::time::Duration {
        let delay = self.base_delay_ms * 2_u64.pow(attempt);
        std::time::Duration::from_millis(delay.min(self.max_delay_ms))
    }
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
    #[serde(alias = "rateLimitPerMin")]
    pub rate_limit_per_min: u64,
    #[serde(default)]
    pub retry: RetryConfig,
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
                "server.sizeLimit must be at least 1 MB".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ShellConfig {
    pub editor: bool,
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

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct RegistryConfig {
    pub default: String,
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

pub fn default_config_path() -> &'static Path {
    Path::new(DEFAULT_CONFIG_PATH)
}
