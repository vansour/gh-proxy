use std::fs;
use std::path::{Component, Path as FsPath, PathBuf};

pub(super) const CONTAINER_WEB_ROOT: &str = "/app/web";
pub(super) const LOCAL_WEB_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frontend/target/dx/gh-proxy-frontend/release/web/public"
);
pub(super) const LOCAL_WEB_ROOT_DISPLAY: &str =
    "frontend/target/dx/gh-proxy-frontend/release/web/public";

pub(super) fn is_safe_relative_path(path: &FsPath) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

pub(super) fn resolve_web_file(relative_path: &FsPath) -> Option<PathBuf> {
    if !is_safe_relative_path(relative_path) {
        return None;
    }

    [CONTAINER_WEB_ROOT, LOCAL_WEB_ROOT]
        .iter()
        .map(|root| FsPath::new(root).join(relative_path))
        .find(|candidate| candidate.exists())
}

pub(super) fn read_web_string(relative_path: &FsPath) -> Option<String> {
    resolve_web_file(relative_path).and_then(|path| fs::read_to_string(path).ok())
}

pub(super) fn read_web_bytes(relative_path: &FsPath) -> Option<Vec<u8>> {
    resolve_web_file(relative_path).and_then(|path| fs::read(path).ok())
}

pub(super) fn content_type_for_path(path: &str) -> &'static str {
    if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".map") {
        "application/json; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}
