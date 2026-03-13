use super::paths::is_safe_relative_path;
use std::path::Path as FsPath;

#[test]
fn rejects_unsafe_relative_paths() {
    assert!(is_safe_relative_path(FsPath::new("assets/app.js")));
    assert!(!is_safe_relative_path(FsPath::new("/etc/passwd")));
    assert!(!is_safe_relative_path(FsPath::new("../secrets.txt")));
    assert!(!is_safe_relative_path(FsPath::new(
        "assets/../../secrets.txt"
    )));
}
