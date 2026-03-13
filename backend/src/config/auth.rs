use http::header::HeaderValue;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AuthConfig {
    pub token: String,
}

impl AuthConfig {
    pub fn authorization_header(
        &self,
    ) -> Result<Option<HeaderValue>, http::header::InvalidHeaderValue> {
        let token = self.token.trim();
        if token.is_empty() {
            return Ok(None);
        }

        let mut value = String::with_capacity(token.len() + 6);
        value.push_str("token ");
        value.push_str(token);
        HeaderValue::from_str(&value).map(Some)
    }
}
