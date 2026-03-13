//! Proxy core modules.

pub mod execute;
pub mod fallback;
pub mod headers;
pub mod resolver;
pub mod stream;

pub use execute::proxy_request;
pub use fallback::proxy_handler;
