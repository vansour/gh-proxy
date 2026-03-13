use super::ConfigError;
use http::header::HeaderName;
use serde::Deserialize;

const DEFAULT_ORIGIN_AUTH_HEADER_NAME: &str = "x-gh-proxy-origin-auth";

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IngressConfig {
    #[serde(alias = "authHeaderName")]
    pub auth_header_name: String,
    #[serde(alias = "authHeaderValue")]
    pub auth_header_value: String,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            auth_header_name: DEFAULT_ORIGIN_AUTH_HEADER_NAME.to_string(),
            auth_header_value: String::new(),
        }
    }
}

impl IngressConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let header_name = self.auth_header_name.trim();
        let header_name = if header_name.is_empty() {
            DEFAULT_ORIGIN_AUTH_HEADER_NAME
        } else {
            header_name
        };
        let normalized = HeaderName::from_bytes(header_name.as_bytes()).map_err(|_| {
            ConfigError::Validation(format!(
                "ingress.auth_header_name '{}' is not a valid HTTP header name",
                self.auth_header_name
            ))
        })?;

        self.auth_header_name = normalized.as_str().to_string();
        self.auth_header_value = self.auth_header_value.trim().to_string();
        Ok(())
    }

    pub fn auth_header_enabled(&self) -> bool {
        !self.auth_header_value.is_empty()
    }
}
