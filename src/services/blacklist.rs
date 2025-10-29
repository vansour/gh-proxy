use crate::{AppState, ProxyError, ProxyResult, config};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
pub struct BlacklistCache {
    rules: Vec<String>,
    last_modified: Option<SystemTime>,
}
impl BlacklistCache {
    fn new() -> Self {
        Self {
            rules: Vec::new(),
            last_modified: None,
        }
    }
    fn is_file_modified(file_path: &str, last_mtime: Option<SystemTime>) -> bool {
        match std::fs::metadata(file_path) {
            Ok(metadata) => match metadata.modified() {
                Ok(current_mtime) => match last_mtime {
                    Some(last) => current_mtime > last,
                    None => true,
                },
                Err(_) => false,
            },
            Err(_) => false,
        }
    }
    async fn load_or_reload(&mut self, config: &config::BlacklistConfig) -> bool {
        if !config.enabled {
            return false;
        }
        if !Self::is_file_modified(&config.blacklist_file, self.last_modified) {
            debug!("Blacklist file has not changed, using cached rules");
            return false;
        }
        match config.load_blacklist() {
            Ok(new_rules) => {
                let old_count = self.rules.len();
                self.rules = new_rules;
                if let Ok(metadata) = std::fs::metadata(&config.blacklist_file)
                    && let Ok(mtime) = metadata.modified()
                {
                    self.last_modified = Some(mtime);
                }
                if old_count == 0 {
                    info!("Loaded {} blacklist entries", self.rules.len());
                } else {
                    info!(
                        "Reloaded blacklist: {} entries (was {} entries)",
                        self.rules.len(),
                        old_count
                    );
                }
                true
            }
            Err(e) => {
                warn!("Failed to load blacklist: {}", e);
                false
            }
        }
    }
}
pub async fn load_blacklist_with_reload(state: &AppState) -> Vec<String> {
    if !state.settings.blacklist.enabled {
        return Vec::new();
    }
    let mut cache = state
        .blacklist_cache
        .get_or_init(|| async { Arc::new(RwLock::new(BlacklistCache::new())) })
        .await
        .write()
        .await;
    cache.load_or_reload(&state.settings.blacklist).await;
    cache.rules.clone()
}
pub fn is_ip_blacklisted(ip: &str, blacklist: &[String]) -> bool {
    for rule in blacklist.iter() {
        if config::BlacklistConfig::ip_matches_rule(ip, rule) {
            return true;
        }
    }
    false
}
pub async fn check_blacklist(state: &AppState, client_ip: Option<String>) -> ProxyResult<()> {
    if !state.settings.blacklist.enabled {
        return Ok(());
    }
    if let Some(client_ip) = client_ip {
        let blacklist = load_blacklist_with_reload(state).await;
        if is_ip_blacklisted(&client_ip, &blacklist) {
            warn!("Blocked request from blacklisted IP: {}", client_ip);
            return Err(ProxyError::AccessDenied(client_ip));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blacklist_cache_new() {
        let cache = BlacklistCache::new();
        assert_eq!(cache.rules.len(), 0);
        assert_eq!(cache.last_modified, None);
    }

    #[test]
    fn test_is_ip_blacklisted_exact_match() {
        let blacklist = vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()];
        assert!(is_ip_blacklisted("192.168.1.1", &blacklist));
        assert!(is_ip_blacklisted("10.0.0.1", &blacklist));
    }

    #[test]
    fn test_is_ip_blacklisted_no_match() {
        let blacklist = vec!["192.168.1.1".to_string()];
        assert!(!is_ip_blacklisted("192.168.1.2", &blacklist));
        assert!(!is_ip_blacklisted("10.0.0.1", &blacklist));
    }

    #[test]
    fn test_is_ip_blacklisted_empty_list() {
        let blacklist: Vec<String> = vec![];
        assert!(!is_ip_blacklisted("192.168.1.1", &blacklist));
    }

    #[test]
    fn test_is_ip_blacklisted_multiple_items() {
        let blacklist = vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.1".to_string(),
            "172.16.0.0/12".to_string(),
        ];
        // Exact matches should work
        assert!(is_ip_blacklisted("10.0.0.1", &blacklist));
        assert!(is_ip_blacklisted("192.168.1.0/24", &blacklist));
    }
}
