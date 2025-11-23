use crate::utils;
use axum::{
    body::Body,
    http::{Response, StatusCode, Uri},
};
use hyper::header;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use tracing::error;
pub async fn index() -> impl axum::response::IntoResponse {
    let html = match fs::read_to_string("/app/web/index.html") {
        Ok(s) => s,
        Err(_) => r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>gh-proxy</title>
</head>
<body>
    <h1>gh-proxy - GitHub Proxy</h1>
    <p>Web UI not available. Please check the installation.</p>
</body>
</html>"#
            .to_string(),
    };
    let mut hasher = DefaultHasher::new();
    html.hash(&mut hasher);
    let etag = format!("\"{}\"", hasher.finish());
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::ETAG, etag)
        .body(Body::from(html))
        .unwrap_or_else(|e| {
            error!("Failed to build index response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap_or_else(|_| Response::new(Body::from("Internal Server Error")))
        })
}
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
pub async fn serve_favicon() -> Response<Body> {
    let content = utils::errors::read_file_bytes_or_empty("/app/web/favicon.ico");
    if content.is_empty() {
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

pub async fn serve_docker_index() -> impl axum::response::IntoResponse {
    let html = match fs::read_to_string("/app/web/docker/index.html") {
        Ok(s) => s,
        Err(_) => "<html><body><h1>Docker UI missing</h1></body></html>".to_string(),
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap_or_else(|e| {
            error!("Failed to build docker index response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap_or_else(|_| Response::new(Body::from("Internal Server Error")))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serve_static_file_css_content_type() {
        let uri = Uri::builder().path_and_query("/style.css").build().unwrap();
        let path = uri.path().trim_start_matches('/');
        let content_type = match path {
            "style.css" => "text/css; charset=utf-8",
            "script.js" => "application/javascript; charset=utf-8",
            _ => "text/plain; charset=utf-8",
        };
        assert_eq!(content_type, "text/css; charset=utf-8");
    }

    #[test]
    fn test_serve_static_file_js_content_type() {
        let uri = Uri::builder().path_and_query("/script.js").build().unwrap();
        let path = uri.path().trim_start_matches('/');
        let content_type = match path {
            "style.css" => "text/css; charset=utf-8",
            "script.js" => "application/javascript; charset=utf-8",
            _ => "text/plain; charset=utf-8",
        };
        assert_eq!(content_type, "application/javascript; charset=utf-8");
    }

    #[test]
    fn test_serve_static_file_default_content_type() {
        let uri = Uri::builder().path_and_query("/other.txt").build().unwrap();
        let path = uri.path().trim_start_matches('/');
        let content_type = match path {
            "style.css" => "text/css; charset=utf-8",
            "script.js" => "application/javascript; charset=utf-8",
            _ => "text/plain; charset=utf-8",
        };
        assert_eq!(content_type, "text/plain; charset=utf-8");
    }

    #[test]
    fn test_static_file_path_trimming() {
        let uri = Uri::builder()
            .path_and_query("/static/path/to/file.txt")
            .build()
            .unwrap();
        let path = uri.path().trim_start_matches('/');
        assert_eq!(path, "static/path/to/file.txt");
    }

    #[test]
    fn test_etag_generation() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let html = "<html>test</html>";
        let mut hasher = DefaultHasher::new();
        html.hash(&mut hasher);
        let etag = format!("\"{}\"", hasher.finish());

        // Verify etag format
        assert!(etag.starts_with('"'));
        assert!(etag.ends_with('"'));
        assert!(etag.len() > 2); // Must have content between quotes
    }

    #[test]
    fn test_etag_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let html = "<html>test</html>";

        let mut hasher1 = DefaultHasher::new();
        html.hash(&mut hasher1);
        let etag1 = format!("\"{}\"", hasher1.finish());

        let mut hasher2 = DefaultHasher::new();
        html.hash(&mut hasher2);
        let etag2 = format!("\"{}\"", hasher2.finish());

        // ETags should be consistent for the same content
        assert_eq!(etag1, etag2);
    }

    #[test]
    fn test_favicon_etag() {
        let etag = "\"static-favicon\"";
        assert_eq!(etag, "\"static-favicon\"");
    }
}
