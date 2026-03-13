use axum::http::Uri;
use tracing::debug;

use crate::config::GitHubConfig;
use crate::errors::{ProxyError, ProxyResult};
use crate::providers::github;

pub fn resolve_target_uri_with_validation(
    uri: &Uri,
    host_guard: &GitHubConfig,
) -> ProxyResult<Uri> {
    let target_uri = super::resolve_fallback_target(uri).map_err(|msg| {
        debug!("Fallback target resolution failed: {}", msg);
        ProxyError::InvalidGitHubUrl(msg)
    })?;
    validate_target_uri(target_uri, host_guard)
}

pub fn validate_target_uri(target_uri: Uri, host_guard: &GitHubConfig) -> ProxyResult<Uri> {
    let target_str = target_uri.to_string();
    let host = target_uri.host().ok_or_else(|| {
        ProxyError::InvalidTarget(format!("Target URI missing host: {}", target_str))
    })?;
    if !host_guard.is_allowed(host) {
        return Err(ProxyError::UnsupportedHost(host.to_string()));
    }
    if github::is_github_web_only_path(&target_str) {
        return Err(ProxyError::GitHubWebPage(target_str));
    }
    if github::is_github_repo_homepage(&target_str) {
        return Err(ProxyError::GitHubRepoHomepage(target_str));
    }
    Ok(target_uri)
}
