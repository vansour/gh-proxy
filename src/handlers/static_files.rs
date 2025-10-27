/// Static file serving handlers
/// Handles serving of HTML, CSS, JavaScript, and favicon files
use axum::{
    body::Body,
    http::{Response, StatusCode, Uri},
};
use hyper::header;
use tracing::error;

use crate::utils;

/// GET / - Serve the main HTML page
pub async fn index() -> impl axum::response::IntoResponse {
    let html = crate::utils::cache::get_index_html();
    let etag = crate::utils::cache::get_index_html_etag();

    // Set Content-Type with UTF-8 charset explicitly
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::ETAG, etag.as_str()),
        ],
        html.clone(),
    )
}

/// GET /style.css - Serve static files
pub async fn serve_static_file(uri: Uri) -> Response<Body> {
    let path = uri.path().trim_start_matches('/');
    let file_path = format!("/app/web/{}", path);

    let content_type = match path {
        "style.css" => "text/css; charset=utf-8",
        "script.js" => "application/javascript; charset=utf-8",
        _ => "text/plain; charset=utf-8",
    };

    let content = utils::errors::read_file_bytes_or_empty(&file_path);

    if content.is_empty() && !std::path::Path::new(&file_path).exists() {
        utils::errors::build_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "File not found".to_string(),
        )
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(content))
            .unwrap_or_else(|e| {
                error!("Failed to build static file response: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()))
            })
    }
}

/// GET /favicon.ico - Serve favicon
pub async fn serve_favicon() -> Response<Body> {
    let content = crate::utils::cache::get_favicon();

    if content.is_empty() {
        // Return a minimal 1x1 transparent ICO if file not found
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "image/x-icon")
            .body(Body::empty())
            .unwrap_or_else(|e| {
                error!("Failed to build favicon response: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()))
            })
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "image/x-icon")
            .header("ETag", "\"static-favicon\"")
            .body(Body::from(content.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to build favicon response: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()))
            })
    }
}
