use std::{collections::HashMap, fs, path::Path, time::Duration};

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
    #[serde(default)]
    pub docker: DockerConfig,
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
        self.docker.finalize()?;
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

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(300) // 5 minutes for large downloads
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
                let list: Vec<String> = serde_json::from_str(&content)
                    .unwrap_or_else(|_| Vec::new());
                Ok(list)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }
    
    pub fn is_blacklisted(&self, url: &str) -> bool {
        if !self.enabled {
            return false;
        }
        // This is a placeholder - in production, you'd cache the blacklist
        self.load_blacklist()
            .unwrap_or_default()
            .iter()
            .any(|pattern| url.contains(pattern))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DockerConfig {
    pub enabled: bool,
    pub auth: bool,
    #[serde(default)]
    pub auther: HashMap<String, String>,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auth: false,
            auther: HashMap::new(),
        }
    }
}

impl DockerConfig {
    fn finalize(&mut self) -> Result<(), ConfigError> {
        // Validate auth configuration
        if self.auth && self.auther.is_empty() {
            return Err(ConfigError::Validation(
                "docker.auth is enabled but no auther credentials provided".into(),
            ));
        }
        Ok(())
    }

    pub fn is_allowed_registry(&self, registry: &str) -> bool {
        if !self.enabled {
            return false;
        }

        let registry = registry.to_ascii_lowercase();
        // List of supported registries
        let allowed = [
            "docker.io",
            "registry-1.docker.io",
            "ghcr.io",
            "gcr.io",
            "registry.k8s.io",
            "nvcr.io",
            "quay.io",
            "mcr.microsoft.com",
            "docker.elastic.co",
        ];

        allowed.iter().any(|&h| h == registry)
    }

    pub fn get_auth(&self, username: &str) -> Option<&str> {
        if !self.auth {
            return None;
        }
        self.auther.get(username).map(|s| s.as_str())
    }
}

// GitHub-related helper structures
pub struct GitHubConfig {
    pub allowed_hosts: Vec<String>,
    pub default_host: String,
}

impl GitHubConfig {
    pub fn new(_auth_token: &str) -> Self {
        Self {
            allowed_hosts: vec![
                "github.com".to_string(),
                "raw.githubusercontent.com".to_string(),
                "api.github.com".to_string(),
                "codeload.github.com".to_string(),
                "objects.githubusercontent.com".to_string(),
                "gist.github.com".to_string(),
            ],
            default_host: "github.com".to_string(),
        }
    }

    pub fn is_allowed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.allowed_hosts.iter().any(|h| h == &host)
    }
}

pub fn default_config_path() -> &'static Path {
    Path::new(DEFAULT_CONFIG_PATH)
}
