use super::ConfigError;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct DebugConfig {
    #[serde(alias = "endpointsEnabled")]
    pub endpoints_enabled: bool,
    #[serde(alias = "metricsEnabled")]
    pub metrics_enabled: bool,
}

impl DebugConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}
