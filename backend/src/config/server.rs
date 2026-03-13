use super::ConfigError;
use serde::Deserialize;

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
    pub(crate) fn finalize(&mut self) {
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
