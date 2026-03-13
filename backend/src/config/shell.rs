use super::ConfigError;
use crate::services::request::normalize_public_base_url;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ShellConfig {
    pub editor: bool,
    #[serde(alias = "publicBaseUrl")]
    pub public_base_url: String,
}

impl ShellConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let trimmed = self.public_base_url.trim();
        if trimmed.is_empty() {
            self.public_base_url.clear();
            return Ok(());
        }

        self.public_base_url = normalize_public_base_url(trimmed).map_err(|err| {
            ConfigError::Validation(format!("shell.public_base_url is invalid: {}", err))
        })?;
        Ok(())
    }
}
