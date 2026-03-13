use super::ConfigError;
use serde::Deserialize;

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
