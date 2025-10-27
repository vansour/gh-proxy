/// Blacklist service for access control
/// Manages IP blacklist loading and matching with file-based hot reload support
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::{AppState, ProxyError, ProxyResult, config};

/// Cached blacklist with file modification time tracking for hot reload
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

    /// Check if the blacklist file has been modified since last load
    fn is_file_modified(file_path: &str, last_mtime: Option<SystemTime>) -> bool {
        match std::fs::metadata(file_path) {
            Ok(metadata) => {
                match metadata.modified() {
                    Ok(current_mtime) => {
                        match last_mtime {
                            Some(last) => current_mtime > last,
                            None => true, // Never loaded before
                        }
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }

    /// Load blacklist from file if it has been modified or never loaded
    async fn load_or_reload(&mut self, config: &config::BlacklistConfig) -> bool {
        if !config.enabled {
            return false;
        }

        // Check if file has been modified
        if !Self::is_file_modified(&config.blacklist_file, self.last_modified) {
            debug!("Blacklist file has not changed, using cached rules");
            return false;
        }

        // Load the file
        match config.load_blacklist() {
            Ok(new_rules) => {
                let old_count = self.rules.len();
                self.rules = new_rules;

                // Update modification time
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

/// Load or reload blacklist with hot reload support
/// Returns the current blacklist rules
pub async fn load_blacklist_with_reload(state: &AppState) -> Vec<String> {
    if !state.settings.blacklist.enabled {
        return Vec::new();
    }

    // Get or initialize the blacklist cache
    let mut cache = state
        .blacklist_cache
        .get_or_init(|| async { Arc::new(RwLock::new(BlacklistCache::new())) })
        .await
        .write()
        .await;

    // Try to reload if file has been modified
    cache.load_or_reload(&state.settings.blacklist).await;

    cache.rules.clone()
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

/// Check if the client IP is blacklisted with hot reload support
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
