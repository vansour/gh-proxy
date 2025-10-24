use std::{fs, path::Path, time::Duration};

use serde::Deserialize;
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

impl ProxyConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        // Normalize entries and validate they are parseable patterns
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

        // Discard any path component that might be present
        if let Some((host_part, _)) = pattern.split_once('/') {
            pattern = host_part;
        }

        // Separate host from optional port
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_pattern_matches_only_same_host() {
        let pattern = HostPattern::parse("github.com").unwrap();
        assert!(pattern.matches("github.com"));
        assert!(!pattern.matches("raw.github.com"));
    }

    #[test]
    fn suffix_pattern_allows_subdomains() {
        let pattern = HostPattern::parse("*.github.com").unwrap();
        assert!(pattern.matches("github.com"));
        assert!(pattern.matches("raw.github.com"));
        assert!(!pattern.matches("example.com"));
    }

    #[test]
    fn parser_trims_scheme_and_path() {
        let pattern = HostPattern::parse("https://*.githubusercontent.com/download").unwrap();
        assert!(pattern.matches("githubusercontent.com"));
        assert!(pattern.matches("raw.githubusercontent.com"));
        assert!(pattern.matches("cdn.raw.githubusercontent.com"));
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        assert!(HostPattern::parse("*").is_err());
        assert!(HostPattern::parse("http://").is_err());
        let mut cfg = ProxyConfig {
            allowed_hosts: vec!["".into()],
        };
        assert!(cfg.validate().is_err());
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(rename = "sizeLimit")]
    pub size_limit: u64, // MB
    #[serde(rename = "connectTimeoutSeconds")]
    pub connect_timeout_secs: u64,
    #[serde(rename = "keepAliveSeconds")]
    pub keep_alive_secs: u64,
    #[serde(rename = "poolMaxIdlePerHost")]
    pub pool_max_idle_per_host: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            size_limit: 125,
            connect_timeout_secs: 30,
            keep_alive_secs: 90,
            pool_max_idle_per_host: 8,
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

    pub fn connect_timeout(&self) -> Option<Duration> {
        if self.connect_timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.connect_timeout_secs))
        }
    }

    pub fn keep_alive(&self) -> Option<Duration> {
        if self.keep_alive_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.keep_alive_secs))
        }
    }

    /// Validate server configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Port must be in valid range
        if self.port == 0 {
            return Err(ConfigError::Validation(
                "server.port cannot be 0".to_string(),
            ));
        }

        // Size limit should be at least 1 MB
        if self.size_limit == 0 {
            return Err(ConfigError::Validation(
                "server.sizeLimit must be at least 1 MB".to_string(),
            ));
        }

        if self.pool_max_idle_per_host == 0 {
            return Err(ConfigError::Validation(
                "server.poolMaxIdlePerHost must be at least 1".to_string(),
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
    #[serde(rename = "logFilePath")]
    pub log_file_path: String,
    #[serde(rename = "maxLogSize")]
    pub max_log_size: u64, // MB
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_file_path: "/app/log/ghproxy.log".to_string(),
            max_log_size: 5,
            level: "info".to_string(),
        }
    }
}

impl LogConfig {
    pub fn max_log_size_bytes(&self) -> u64 {
        self.max_log_size * 1024 * 1024 // Convert MB to bytes
    }

    pub fn get_level(&self) -> &str {
        &self.level
    }

    /// Validate log configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Log level should be valid
        match self.level.to_lowercase().as_str() {
            "debug" | "info" | "warn" | "error" | "trace" | "none" => {}
            _ => {
                return Err(ConfigError::Validation(format!(
                    "Invalid log level '{}'. Valid values: debug, info, warn, error, trace, none",
                    self.level
                )));
            }
        }

        // Max log size should be reasonable (1MB to 1GB)
        if self.max_log_size == 0 {
            return Err(ConfigError::Validation(
                "log.maxLogSize must be at least 1 MB".to_string(),
            ));
        }
        if self.max_log_size > 1024 {
            return Err(ConfigError::Validation(
                "log.maxLogSize cannot exceed 1024 MB (1 GB)".to_string(),
            ));
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BlacklistConfig {
    pub enabled: bool,
    #[serde(rename = "blacklistFile")]
    pub blacklist_file: String,
}

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
    pub fn load_blacklist(&self) -> Result<Vec<String>, std::io::Error> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        match fs::read_to_string(&self.blacklist_file) {
            Ok(content) => {
                // Try to parse as the new format with version and rules
                if let Ok(blacklist) = serde_json::from_str::<BlacklistFile>(&content) {
                    Ok(blacklist.rules)
                } else {
                    // Fallback to old format (direct array)
                    let list: Vec<String> =
                        serde_json::from_str(&content).unwrap_or_else(|_| Vec::new());
                    Ok(list)
                }
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

        for rule in rules.iter() {
            if Self::ip_matches_rule(ip, rule) {
                return true;
            }
        }

        false
    }

    /// Check if an IP matches a blacklist rule (public for lazy loading)
    pub fn ip_matches_rule(ip: &str, rule: &str) -> bool {
        // Exact match
        if ip == rule {
            return true;
        }

        // CIDR notation (e.g., 192.168.1.0/24)
        if rule.contains('/') {
            return Self::ip_in_cidr(ip, rule);
        }

        // IP range (e.g., 192.168.1.1-192.168.1.255)
        if rule.contains('-') {
            return Self::ip_in_range(ip, rule);
        }

        // Wildcard (e.g., 192.168.1.*)
        if rule.contains('*') {
            return Self::ip_matches_wildcard(ip, rule);
        }

        false
    }

    fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let network = parts[0];
        let prefix_len: u32 = match parts[1].parse() {
            Ok(len) => len,
            Err(_) => return false,
        };

        let ip_num = match Self::ip_to_u32(ip) {
            Some(num) => num,
            None => return false,
        };

        let network_num = match Self::ip_to_u32(network) {
            Some(num) => num,
            None => return false,
        };

        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };

        (ip_num & mask) == (network_num & mask)
    }

    fn ip_in_range(ip: &str, range: &str) -> bool {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            return false;
        }

        let start = match Self::ip_to_u32(parts[0].trim()) {
            Some(num) => num,
            None => return false,
        };

        let end = match Self::ip_to_u32(parts[1].trim()) {
            Some(num) => num,
            None => return false,
        };

        let ip_num = match Self::ip_to_u32(ip) {
            Some(num) => num,
            None => return false,
        };

        ip_num >= start && ip_num <= end
    }

    fn ip_matches_wildcard(ip: &str, pattern: &str) -> bool {
        let ip_parts: Vec<&str> = ip.split('.').collect();
        let pattern_parts: Vec<&str> = pattern.split('.').collect();

        if ip_parts.len() != 4 || pattern_parts.len() != 4 {
            return false;
        }

        for i in 0..4 {
            if pattern_parts[i] != "*" && ip_parts[i] != pattern_parts[i] {
                return false;
            }
        }

        true
    }

    fn ip_to_u32(ip: &str) -> Option<u32> {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return None;
        }

        let mut result: u32 = 0;
        for part in parts {
            let octet: u32 = part.parse().ok()?;
            if octet > 255 {
                return None;
            }
            result = (result << 8) | octet;
        }

        Some(result)
    }
}

// GitHub-related helper structures
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

    /// Check if a host is permitted by configuration
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
