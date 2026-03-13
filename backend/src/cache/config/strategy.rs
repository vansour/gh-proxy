use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheStrategy {
    Disabled,
    MemoryOnly,
    #[default]
    MemoryWithCdn,
}
