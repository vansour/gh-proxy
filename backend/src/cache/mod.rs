//! 多级缓存系统
//!
//! - 一级缓存：使用 moka 实现的内存缓存
//! - 二级缓存：通过 Cache-Control 头委托给 Cloudflare CDN

pub mod config;
pub mod key;
pub mod manager;
pub mod metrics;
pub mod response_cache;
pub mod utils;
