//! HTTP header manipulation for proxy requests and responses.

mod github;
mod request;
mod response;
mod vary;

pub use github::apply_github_headers;
pub use request::sanitize_request_headers;
pub use response::{fix_content_type_header, sanitize_response_headers};
pub use vary::add_vary_header;
