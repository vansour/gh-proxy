use http::header::HeaderValue;
use serde::Deserialize;
use std::{fmt, fs, path::Path};
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
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub registry: RegistryConfig,
    #[serde(default)]
    pub shell: ShellConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub blacklist: BlacklistConfig,
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
        self.proxy.validate()?;
        self.log.validate()?;
        Ok(())
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    #[serde(rename = "allowedHosts")]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RegistryConfig {
    /// Default upstream registry (e.g. docker.io)
    #[serde(rename = "default")]
    pub default: String,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            default: "docker.io".to_string(),
        }
    }
}
impl ProxyConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let mut normalized = Vec::with_capacity(self.allowed_hosts.len());
        for entry in self.allowed_hosts.iter() {
            let pattern = entry.trim();
            if pattern.is_empty() {
                return Err(ConfigError::Validation(
                    "proxy.allowedHosts cannot include empty values".to_string(),
                ));
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
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(rename = "sizeLimit")]
    pub size_limit: u64,
    #[serde(rename = "requestTimeoutSecs")]
    pub request_timeout_secs: u64,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u32,
    #[serde(rename = "permitAcquireTimeoutSecs")]
    pub permit_acquire_timeout_secs: u64,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            size_limit: 125,
            request_timeout_secs: 60,
            max_concurrent_requests: 50,
            permit_acquire_timeout_secs: 10,
        }
    }
}
impl ServerConfig {
    fn finalize(&mut self) {
        if self.host.is_empty() {
            self.host = "0.0.0.0".to_string();
        }
    }
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::Validation(
                "server.port cannot be 0".to_string(),
            ));
        }
        if self.size_limit == 0 {
            return Err(ConfigError::Validation(
                "server.sizeLimit must be at least 1 MB".to_string(),
            ));
        }
        if self.request_timeout_secs == 0 {
            return Err(ConfigError::Validation(
                "server.requestTimeoutSecs must be at least 1 second".to_string(),
            ));
        }
        if self.max_concurrent_requests == 0 {
            return Err(ConfigError::Validation(
                "server.maxConcurrentRequests must be at least 1".to_string(),
            ));
        }
        if self.permit_acquire_timeout_secs == 0 {
            return Err(ConfigError::Validation(
                "server.permitAcquireTimeoutSecs must be at least 1".to_string(),
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
impl ShellConfig {
    pub fn is_editor_enabled(&self) -> bool {
        self.editor
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    pub log_file_path: String,
    pub level: String,
}
impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_file_path: "/app/log/ghproxy.log".to_string(),
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
                    "Invalid log level '{}'. Valid values: debug, info, warn, error, trace, none",
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
    pub fn has_token(&self) -> bool {
        !self.token.trim().is_empty()
    }

    pub fn authorization_header(
        &self,
    ) -> Result<Option<HeaderValue>, http::header::InvalidHeaderValue> {
        if !self.has_token() {
            return Ok(None);
        }

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
pub struct BlacklistConfig {
    pub enabled: bool,
    #[serde(rename = "blacklistFile")]
    pub blacklist_file: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlacklistRule {
    Exact(u32),
    Cidr { network: u32, mask: u32 },
    Range { start: u32, end: u32 },
    Wildcard { segments: [Option<u8>; 4] },
}

impl BlacklistRule {
    pub fn from_str(rule: &str) -> Result<Self, BlacklistRuleParseError> {
        let trimmed = rule.trim();
        if trimmed.is_empty() {
            return Err(BlacklistRuleParseError);
        }
        if let Some((network, prefix)) = trimmed.split_once('/') {
            let prefix_len: u32 = prefix.parse().map_err(|_| BlacklistRuleParseError)?;
            if prefix_len > 32 {
                return Err(BlacklistRuleParseError);
            }
            let network_num = BlacklistConfig::ip_to_u32(network).ok_or(BlacklistRuleParseError)?;
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            return Ok(BlacklistRule::Cidr {
                network: network_num & mask,
                mask,
            });
        }
        if let Some((start, end)) = trimmed.split_once('-') {
            let start_num =
                BlacklistConfig::ip_to_u32(start.trim()).ok_or(BlacklistRuleParseError)?;
            let end_num = BlacklistConfig::ip_to_u32(end.trim()).ok_or(BlacklistRuleParseError)?;
            if start_num > end_num {
                return Err(BlacklistRuleParseError);
            }
            return Ok(BlacklistRule::Range {
                start: start_num,
                end: end_num,
            });
        }
        if trimmed.contains('*') {
            let mut segments = [None; 4];
            let mut parts = trimmed.split('.');
            for segment in segments.iter_mut() {
                match parts.next() {
                    Some("*") => {
                        *segment = None;
                    }
                    Some(value) => {
                        let octet: u8 = value.parse().map_err(|_| BlacklistRuleParseError)?;
                        *segment = Some(octet);
                    }
                    None => return Err(BlacklistRuleParseError),
                }
            }
            if parts.next().is_some() {
                return Err(BlacklistRuleParseError);
            }
            return Ok(BlacklistRule::Wildcard { segments });
        }
        let ip_num = BlacklistConfig::ip_to_u32(trimmed).ok_or(BlacklistRuleParseError)?;
        Ok(BlacklistRule::Exact(ip_num))
    }

    pub fn matches(&self, ip_num: u32, octets: &[u8; 4]) -> bool {
        match self {
            BlacklistRule::Exact(expected) => ip_num == *expected,
            BlacklistRule::Cidr { network, mask } => (ip_num & mask) == (*network & mask),
            BlacklistRule::Range { start, end } => ip_num >= *start && ip_num <= *end,
            BlacklistRule::Wildcard { segments } => {
                segments
                    .iter()
                    .zip(octets.iter())
                    .all(|(segment, octet)| match segment {
                        Some(expected) => expected == octet,
                        None => true,
                    })
            }
        }
    }
}

#[derive(Debug)]
pub struct BlacklistRuleParseError;

impl fmt::Display for BlacklistRuleParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid blacklist rule")
    }
}

impl std::error::Error for BlacklistRuleParseError {}
#[derive(Debug, Deserialize)]
struct BlacklistFile {
    rules: Vec<String>,
}
impl Default for BlacklistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            blacklist_file: "/app/config/blacklist.json".to_string(),
        }
    }
}
impl BlacklistConfig {
    pub fn load_blacklist(&self) -> Result<Vec<BlacklistRule>, std::io::Error> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        match fs::read_to_string(&self.blacklist_file) {
            Ok(content) => {
                let parsed_strings =
                    if let Ok(blacklist) = serde_json::from_str::<BlacklistFile>(&content) {
                        blacklist.rules
                    } else {
                        serde_json::from_str::<Vec<String>>(&content).unwrap_or_else(|_| Vec::new())
                    };
                Ok(Self::parse_rules(parsed_strings))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
    pub fn is_ip_blacklisted(&self, ip: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let rules = match self.load_blacklist() {
            Ok(rules) => rules,
            Err(_) => return false,
        };
        let ip_num = match Self::ip_to_u32(ip) {
            Some(num) => num,
            None => return false,
        };
        let octets = ip_num.to_be_bytes();
        rules.iter().any(|rule| rule.matches(ip_num, &octets))
    }

    fn parse_rules(raw_rules: Vec<String>) -> Vec<BlacklistRule> {
        let mut parsed = Vec::with_capacity(raw_rules.len());
        for rule in raw_rules {
            match BlacklistRule::from_str(&rule) {
                Ok(parsed_rule) => parsed.push(parsed_rule),
                Err(_) => tracing::warn!("Ignoring invalid blacklist rule: {}", rule),
            }
        }
        parsed
    }

    pub(crate) fn ip_to_u32(ip: &str) -> Option<u32> {
        let mut parts = ip.split('.');
        let mut result: u32 = 0;
        for _ in 0..4 {
            let part = parts.next()?;
            let octet: u32 = part.parse().ok()?;
            if octet > 255 {
                return None;
            }
            result = (result << 8) | octet;
        }
        if parts.next().is_some() {
            return None;
        }
        Some(result)
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
pub fn default_config_path() -> &'static Path {
    Path::new(DEFAULT_CONFIG_PATH)
}
