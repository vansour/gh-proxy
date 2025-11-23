use crate::{AppState, ProxyError, ProxyResult, config};
use config::BlacklistRule;
use notify::{Event, EventKind, RecursiveMode, Watcher, recommended_watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, mpsc};
use tokio::time;
use tracing::{debug, error, info, warn};

// Buffer size for blacklist event channel.
// 32 was chosen as a reasonable default to handle bursts of file events
// without overwhelming the channel, based on expected event rates and system usage.
const BLACKLIST_EVENT_BUFFER: usize = 32;
const BLACKLIST_RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);

struct BlacklistCache {
    rules: Arc<Vec<BlacklistRule>>,
    last_modified: Option<SystemTime>,
}

impl BlacklistCache {
    fn new() -> Self {
        Self {
            rules: Arc::new(Vec::new()),
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

    fn load_or_reload(&mut self, config: &config::BlacklistConfig) -> bool {
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
                self.rules = Arc::new(new_rules);

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

#[derive(Clone)]
pub struct BlacklistState {
    enabled: bool,
    rules: Arc<RwLock<Arc<Vec<BlacklistRule>>>>,
}

impl BlacklistState {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            rules: Arc::new(RwLock::new(Arc::new(Vec::new()))),
        }
    }

    pub async fn initialize(config: config::BlacklistConfig) -> Self {
        if !config.enabled {
            return Self::disabled();
        }

        let config = Arc::new(config);
        let rules = Arc::new(RwLock::new(Arc::new(Vec::new())));
        let mut cache = BlacklistCache::new();

        // Perform an initial load synchronously so requests see the latest data.
        let _ = cache.load_or_reload(&config);
        {
            let mut guard = rules.write().await;
            *guard = Arc::clone(&cache.rules);
        }

        spawn_blacklist_watcher(Arc::clone(&config), Arc::clone(&rules), cache);

        Self {
            enabled: true,
            rules,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub async fn current_rules(&self) -> Arc<Vec<BlacklistRule>> {
        let guard = self.rules.read().await;
        Arc::clone(&*guard)
    }
}

fn spawn_blacklist_watcher(
    config: Arc<config::BlacklistConfig>,
    rules: Arc<RwLock<Arc<Vec<BlacklistRule>>>>,
    mut cache: BlacklistCache,
) {
    let target_path = PathBuf::from(&config.blacklist_file);
    let watch_root = target_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let (tx, mut rx) = mpsc::channel::<()>(BLACKLIST_EVENT_BUFFER);

    tokio::spawn(async move {
        let watcher = recommended_watcher({
            let tx = tx.clone();
            let target_path = target_path.clone();
            move |result: notify::Result<Event>| match result {
                Ok(event) => {
                    if should_reload(&event, &target_path) {
                        debug!(?event, "Blacklist file change detected");
                        let _ = tx.blocking_send(());
                    }
                }
                Err(err) => warn!("Blacklist watcher error: {}", err),
            }
        });

        let mut watcher = match watcher {
            Ok(watcher) => watcher,
            Err(err) => {
                error!("Failed to initialize blacklist watcher: {}", err);
                return;
            }
        };

        if let Err(err) = watcher.watch(&watch_root, RecursiveMode::NonRecursive) {
            error!(
                "Failed to watch blacklist path '{}': {}",
                watch_root.display(),
                err
            );
            return;
        }

        // Explicitly drop the sender to close the channel when the watcher closure no longer needs to send.
        // This ensures the receive loop terminates gracefully when no more events can arrive.

        while rx.recv().await.is_some() {
            time::sleep(BLACKLIST_RELOAD_DEBOUNCE).await;

            if cache.load_or_reload(&config) {
                let mut guard = rules.write().await;
                *guard = Arc::clone(&cache.rules);
            }
        }
    });
}

fn should_reload(event: &Event, target: &Path) -> bool {
    path_matches_any(&event.paths, target)
        && matches!(
            event.kind,
            EventKind::Create(_)
                | EventKind::Modify(_)
                | EventKind::Remove(_)
                | EventKind::Other
                | EventKind::Any
        )
}

fn path_matches_any(paths: &[PathBuf], target: &Path) -> bool {
    paths.iter().any(|path| path_matches(path, target))
}

fn path_matches(path: &Path, target: &Path) -> bool {
    if path == target {
        return true;
    }

    match (path.file_name(), target.file_name()) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

pub fn is_ip_blacklisted(ip: &str, blacklist: &[BlacklistRule]) -> bool {
    let ip_num = match config::BlacklistConfig::ip_to_u32(ip) {
        Some(value) => value,
        None => return false,
    };
    let octets = ip_num.to_be_bytes();
    blacklist.iter().any(|rule| rule.matches(ip_num, &octets))
}
pub async fn check_blacklist(state: &AppState, client_ip: Option<String>) -> ProxyResult<()> {
    if !state.blacklist.is_enabled() {
        return Ok(());
    }
    if let Some(client_ip) = client_ip {
        let blacklist = state.blacklist.current_rules().await;
        if is_ip_blacklisted(&client_ip, blacklist.as_ref()) {
            warn!("Blocked request from blacklisted IP: {}", client_ip);
            return Err(ProxyError::AccessDenied(client_ip));
        }
    }
    Ok(())
}
