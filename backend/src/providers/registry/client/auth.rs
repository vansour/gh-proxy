use super::{CachedToken, DockerProxy, TOKEN_CACHE_MAX_SIZE, TokenResponse, registry_host_label};
use crate::infra;
use crate::services::client::{HttpError, get_bytes, get_json, head_request, request_streaming};
use bytes::Bytes;
use std::collections::HashMap;
use std::time::{Duration, Instant};

impl DockerProxy {
    fn cloned_headers(extra_headers: Option<Vec<(&str, &str)>>) -> Option<Vec<(String, String)>> {
        extra_headers.as_ref().map(|headers| {
            headers
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect()
        })
    }

    async fn bearer_token_from_challenge(&self, headers: &hyper::HeaderMap) -> Option<String> {
        let www_auth = headers.get("www-authenticate")?;
        let challenge = www_auth.to_str().ok()?;
        if !challenge.to_ascii_lowercase().starts_with("bearer") {
            tracing::warn!(
                "Registry authentication challenge is not bearer-based: {}",
                challenge
            );
            return None;
        }

        self.request_bearer_token(challenge).await.ok()
    }

    pub(crate) async fn fetch_with_auth(
        &self,
        _method: hyper::Method,
        url: &str,
        extra_headers: Option<Vec<(&str, &str)>>,
    ) -> Result<(hyper::StatusCode, hyper::HeaderMap, Bytes), HttpError> {
        let headers = Self::cloned_headers(extra_headers.clone());
        let (status, resp_headers, body) = get_bytes(&self.client, url, extra_headers, 60).await?;

        if status == hyper::StatusCode::UNAUTHORIZED
            && let Some(token) = self.bearer_token_from_challenge(&resp_headers).await
        {
            let mut auth_headers = headers.unwrap_or_default();
            auth_headers.push(("Authorization".to_string(), format!("Bearer {}", token)));

            return get_bytes(
                &self.client,
                url,
                Some(
                    auth_headers
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .collect(),
                ),
                60,
            )
            .await;
        }

        Ok((status, resp_headers, body))
    }

    pub(crate) async fn fetch_streaming_with_auth(
        &self,
        method: hyper::Method,
        url: &str,
        extra_headers: Option<Vec<(&str, &str)>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, HttpError> {
        let headers = Self::cloned_headers(extra_headers);
        let response =
            request_streaming(&self.client, method.clone(), url, headers.clone(), 60).await?;

        if response.status() == hyper::StatusCode::UNAUTHORIZED
            && let Some(token) = self.bearer_token_from_challenge(response.headers()).await
        {
            let mut auth_headers = headers.unwrap_or_default();
            auth_headers.push(("Authorization".to_string(), format!("Bearer {}", token)));

            return request_streaming(&self.client, method, url, Some(auth_headers), 60).await;
        }

        Ok(response)
    }

    pub(crate) async fn head_with_auth(
        &self,
        url: &str,
        extra_headers: Option<Vec<(&str, &str)>>,
    ) -> Result<(hyper::StatusCode, hyper::HeaderMap), HttpError> {
        let headers = Self::cloned_headers(extra_headers.clone());
        let (status, resp_headers) = head_request(&self.client, url, extra_headers, 60).await?;

        if status == hyper::StatusCode::UNAUTHORIZED
            && let Some(token) = self.bearer_token_from_challenge(&resp_headers).await
        {
            let mut auth_headers = headers.unwrap_or_default();
            auth_headers.push(("Authorization".to_string(), format!("Bearer {}", token)));

            return head_request(
                &self.client,
                url,
                Some(
                    auth_headers
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .collect(),
                ),
                60,
            )
            .await;
        }

        Ok((status, resp_headers))
    }

    async fn request_bearer_token(&self, www_authenticate_header: &str) -> Result<String, String> {
        fn parse_kv_pairs(s: &str) -> HashMap<String, String> {
            let mut values = HashMap::new();
            for pair in s.split(',') {
                if let Some((key, value)) = pair.split_once('=') {
                    values.insert(
                        key.trim().trim_matches('"').to_ascii_lowercase(),
                        value.trim().trim_matches('"').to_string(),
                    );
                }
            }
            values
        }

        let trimmed = www_authenticate_header.trim();
        let rest = match trimmed.find(char::is_whitespace) {
            Some(index) => &trimmed[index..],
            None => "",
        }
        .trim();

        let pairs = parse_kv_pairs(rest);
        let realm = match pairs.get("realm") {
            Some(value) => value.clone(),
            None => return Err("WWW-Authenticate header missing realm".to_string()),
        };
        let service = pairs.get("service").cloned().unwrap_or_default();
        let scope = pairs.get("scope").cloned().unwrap_or_default();

        let cache_key = format!("{}|{}|{}", realm, service, scope);

        {
            let cache = self.token_cache.read().await;
            if let Some(entry) = cache.get(&cache_key)
                && entry.expires_at > Instant::now()
            {
                infra::metrics::record_registry_token_cache_hit(&registry_host_label(&realm));
                tracing::debug!("Token cache hit for scope: {}", scope);
                return Ok(entry.token.clone());
            }
        }

        tracing::debug!("Token cache miss, fetching for scope: {}", scope);

        let mut token_url = realm.clone();
        let mut first_param = true;
        if !service.is_empty() {
            token_url.push_str(if first_param { "?" } else { "&" });
            token_url.push_str("service=");
            token_url.push_str(&urlencoding::encode(&service));
            first_param = false;
        }
        if !scope.is_empty() {
            token_url.push_str(if first_param { "?" } else { "&" });
            token_url.push_str("scope=");
            token_url.push_str(&urlencoding::encode(&scope));
        }

        let registry_host = registry_host_label(&realm);
        let start = Instant::now();
        let token_resp: TokenResponse = match get_json(&self.client, &token_url, None, 10).await {
            Ok(response) => {
                infra::metrics::record_registry_token_request(
                    &registry_host,
                    "success",
                    start.elapsed().as_secs_f64(),
                );
                response
            }
            Err(error) => {
                infra::metrics::record_registry_token_request(
                    &registry_host,
                    "error",
                    start.elapsed().as_secs_f64(),
                );
                return Err(error.0);
            }
        };

        let token = token_resp
            .token
            .or(token_resp.access_token)
            .ok_or_else(|| "token not found in token response".to_string())?;

        let expires_in_secs = token_resp
            .expires_in
            .unwrap_or(60)
            .saturating_sub(10)
            .max(10);
        let expires_at = Instant::now() + Duration::from_secs(expires_in_secs);

        {
            let mut cache = self.token_cache.write().await;
            let now = Instant::now();
            cache.retain(|_, entry| entry.expires_at > now);

            if cache.len() >= TOKEN_CACHE_MAX_SIZE {
                let to_remove = cache.len() - TOKEN_CACHE_MAX_SIZE + 1;
                let mut entries: Vec<_> = cache
                    .iter()
                    .map(|(key, entry)| (key.clone(), entry.expires_at))
                    .collect();
                entries.sort_by_key(|(_, expires_at)| *expires_at);
                for (key, _) in entries.into_iter().take(to_remove) {
                    cache.remove(&key);
                }
            }

            cache.insert(
                cache_key,
                CachedToken {
                    token: token.clone(),
                    expires_at,
                },
            );
        }

        Ok(token)
    }
}
