/// Blacklist service for access control
/// Manages IP blacklist loading and matching
use tracing::{info, warn};

use crate::{AppState, ProxyError, ProxyResult, config};

/// Load blacklist lazily (only once, on first use)
pub async fn load_blacklist_lazy(state: &AppState) -> &Vec<String> {
    state
        .blacklist_cache
        .get_or_init(|| async {
            match state.settings.blacklist.load_blacklist() {
                Ok(list) => {
                    info!("Loaded {} blacklist entries (lazy)", list.len());
                    list
                }
                Err(e) => {
                    warn!("Failed to load blacklist: {}", e);
                    Vec::new()
                }
            }
        })
        .await
}

/// Check if an IP matches any blacklist rule
pub fn is_ip_blacklisted(ip: &str, blacklist: &[String]) -> bool {
    for rule in blacklist.iter() {
        if config::BlacklistConfig::ip_matches_rule(ip, rule) {
            return true;
        }
    }
    false
}

/// Check if the client IP is blacklisted
pub async fn check_blacklist(state: &AppState, client_ip: Option<String>) -> ProxyResult<()> {
    if !state.settings.blacklist.enabled {
        return Ok(());
    }

    if let Some(client_ip) = client_ip {
        let blacklist = load_blacklist_lazy(state).await;

        if is_ip_blacklisted(&client_ip, blacklist) {
            warn!("Blocked request from blacklisted IP: {}", client_ip);
            return Err(ProxyError::AccessDenied(client_ip));
        }
    }

    Ok(())
}
