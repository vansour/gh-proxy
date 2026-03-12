//! Middleware for request lifecycle management.

pub mod ingress;
pub mod lifecycle;
pub mod origin_auth;
pub mod rate_limit;
pub mod request_metrics;
pub mod response_hardening;

pub use ingress::ingress_guard_middleware;
pub use lifecycle::{RequestLifecycle, RequestPermitGuard};
pub use origin_auth::origin_auth_middleware;
pub use rate_limit::{RateLimiter, rate_limit_middleware};
pub use request_metrics::{mark_response_duration_recorded, request_metrics_middleware};
pub use response_hardening::response_hardening_middleware;
