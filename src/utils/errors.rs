// Error handling utilities for common operations
// Provides safe alternatives to unwrap() with proper logging and recovery

use std::fs;
use std::path::Path;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use hyper::header;
use tracing::{error, warn};

/// Safely read a file and return its contents or a default value with logging
#[allow(dead_code)]
pub fn read_file_or_default<P: AsRef<Path>>(path: P, default: String) -> String {
    match fs::read_to_string(path.as_ref()) {
        Ok(content) => content,
        Err(e) => {
            warn!(
                "Failed to read file '{}': {}. Using default content.",
                path.as_ref().display(),
                e
            );
            default
        }
    }
}

/// Safely read a binary file and return contents or empty bytes with logging
pub fn read_file_bytes_or_empty<P: AsRef<Path>>(path: P) -> Vec<u8> {
    match fs::read(path.as_ref()) {
        Ok(content) => content,
        Err(e) => {
            warn!(
                "Failed to read file '{}': {}. Returning empty content.",
                path.as_ref().display(),
                e
            );
            Vec::new()
        }
    }
}

/// Safely build an HTTP response with proper error handling
pub fn build_response(
    status: StatusCode,
    content_type: &str,
    body: String,
) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap_or_else(|e| {
            error!("Failed to build HTTP response: {}. Returning INTERNAL_SERVER_ERROR.", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from("Internal Server Error"))
                .unwrap()
        })
}

/// Safely parse string to a specific type with logging
#[allow(dead_code)]
pub fn parse_with_default<T: std::str::FromStr + Default>(
    input: &str,
    context: &str,
) -> T {
    match input.parse::<T>() {
        Ok(value) => value,
        Err(_) => {
            warn!(
                "Failed to parse '{}' to the expected type. Using default value.",
                context
            );
            T::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_file_or_default() {
        let content = read_file_or_default("/nonexistent/file.txt", "default".to_string());
        assert_eq!(content, "default");
    }

    #[test]
    fn test_parse_with_default() {
        let result: u16 = parse_with_default("invalid", "test_parse");
        assert_eq!(result, 0);
    }
}
