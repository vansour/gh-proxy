use axum::http::Uri;

pub fn should_disable_compression_for_request(uri: &Uri) -> bool {
    fn has_extension(path: &str, ext: &str) -> bool {
        path.rsplit_once('.')
            .map(|(_, candidate)| candidate.eq_ignore_ascii_case(ext))
            .unwrap_or(false)
    }

    let path = uri.path();
    if has_extension(path, "sh") || has_extension(path, "bash") || has_extension(path, "zsh") {
        return true;
    }
    if has_extension(path, "html") || has_extension(path, "htm") || has_extension(path, "xml") {
        return true;
    }
    if has_extension(path, "md") || has_extension(path, "markdown") || has_extension(path, "txt") {
        return true;
    }
    if has_extension(path, "json") || has_extension(path, "yaml") || has_extension(path, "yml") {
        return true;
    }
    false
}
