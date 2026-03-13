use super::cache::{FAVICON, INDEX_HTML, STATIC_CACHE_CONTROL};
use super::paths::{content_type_for_path, resolve_web_file};
use super::responses::build_cached_response;
use crate::utils;
use axum::{
    body::Body,
    extract::Path,
    http::{Response, StatusCode},
    response::IntoResponse,
};
use std::path::Path as FsPath;
use tracing::error;

pub async fn index() -> impl IntoResponse {
    build_cached_response(&INDEX_HTML)
}

pub async fn serve_favicon() -> Response<Body> {
    if FAVICON.content.is_empty() {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(hyper::header::CONTENT_TYPE, "image/x-icon")
            .body(Body::empty())
            .unwrap_or_else(|err| {
                error!("Failed to build favicon response: {}", err);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()))
            })
    } else {
        build_cached_response(&FAVICON)
    }
}

pub async fn serve_static_asset(Path(path): Path<String>) -> Response<Body> {
    let relative_path = FsPath::new("assets").join(&path);
    let Some(asset_path) = resolve_web_file(&relative_path) else {
        return utils::errors::build_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "File not found".to_string(),
        );
    };
    let asset_path = asset_path.to_string_lossy().into_owned();
    let content = utils::errors::read_file_bytes_or_empty_async(&asset_path).await;

    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, content_type_for_path(&path))
        .header(hyper::header::CACHE_CONTROL, STATIC_CACHE_CONTROL)
        .body(Body::from(content))
        .unwrap_or_else(|err| {
            error!("Failed to build static asset response: {}", err);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty()))
        })
}
