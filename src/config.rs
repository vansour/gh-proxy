use std::{fs, path::Path};

use serde::Deserialize;
use serde_json;
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
        self.log.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(rename = "sizeLimit")]
    pub size_limit: u64, // MB
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            size_limit: 125,
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

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ShellConfig {
    pub editor: bool,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self { editor: false }
    }
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

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub token: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token: String::new(),
        }
    }
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
}

impl GitHubConfig {
    pub fn new(_auth_token: &str) -> Self {
        Self {
            default_host: "github.com".to_string(),
        }
    }

    /// Check if a host is a valid GitHub domain
    /// Supports *.github.com and *.githubusercontent.com domains
    pub fn is_allowed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        Self::is_github_domain(&host)
    }

    /// Check if a host is a GitHub domain
    /// Matches any domain ending with .github.com or .githubusercontent.com (including subdomains)
    pub fn is_github_domain(host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        host.ends_with(".github.com") || 
        host == "github.com" ||
        host.ends_with(".githubusercontent.com") || 
        host == "raw.githubusercontent.com" ||
        host == "gist.github.com" ||
        // Support custom GitHub domains in enterprise deployments
        host.contains("github") && (host.contains(".com") || host.contains(".io") || host.contains(".org"))
    }
}

pub fn default_config_path() -> &'static Path {
    Path::new(DEFAULT_CONFIG_PATH)
}
