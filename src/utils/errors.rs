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
