//! HTTP client utilities.

mod build;
mod error;
mod requests;

pub use build::build_client;
pub use error::HttpError;
pub use requests::{get_bytes, get_json, head_request, request_streaming};

#[cfg(test)]
mod tests;
