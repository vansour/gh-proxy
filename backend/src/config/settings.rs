use super::{
    AuthConfig, ConfigError, DebugConfig, IngressConfig, LogConfig, ProxyConfig, RateLimitConfig,
    RegistryConfig, ServerConfig, ShellConfig,
};
use crate::cache::config as cache_config;
use serde::Deserialize;
use std::{fs, path::PathBuf};

const CONTAINER_CONFIG_PATH: &str = "/app/config/config.toml";
const LOCAL_CONFIG_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/config/config.toml");

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

pub fn default_config_path() -> PathBuf {
    [CONTAINER_CONFIG_PATH, LOCAL_CONFIG_PATH]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .unwrap_or_else(|| PathBuf::from(CONTAINER_CONFIG_PATH))
}
