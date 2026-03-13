use super::ConfigError;
use serde::Deserialize;

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
