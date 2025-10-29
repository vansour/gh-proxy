use axum::body::Body;
use axum::http::{Response, StatusCode};
use hyper::header;
use std::fs;
use std::path::Path;
use tracing::{error, warn};
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
pub fn build_response(status: StatusCode, content_type: &str, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap_or_else(|e| {
            error!(
                "Failed to build HTTP response: {}. Returning INTERNAL_SERVER_ERROR.",
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from("Internal Server Error"))
                .unwrap_or_else(|_| Response::new(Body::from("Internal Server Error")))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_file_bytes_or_empty_nonexistent() {
        // Test reading a file that doesn't exist
        let result = read_file_bytes_or_empty("/nonexistent/path/file.txt");
        assert!(result.is_empty());
    }

    #[test]
    fn test_read_file_bytes_or_empty_temp_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        let content = b"test content";
        temp_file.write_all(content).unwrap();
        temp_file.flush().unwrap();

        let result = read_file_bytes_or_empty(temp_file.path());
        assert_eq!(result, content);
    }

    #[test]
    fn test_build_response_success() {
        let response = build_response(StatusCode::OK, "text/plain", "Hello World".to_string());
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_build_response_with_content_type() {
        let response = build_response(
            StatusCode::NOT_FOUND,
            "application/json",
            r#"{"error":"not found"}"#.to_string(),
        );
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let content_type = response.headers().get(header::CONTENT_TYPE).unwrap();
        assert_eq!(content_type, "application/json");
    }
}
