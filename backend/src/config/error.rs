use thiserror::Error;

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
