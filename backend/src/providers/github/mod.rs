mod handler;
mod target;
mod url;

pub use handler::github_proxy;
pub use target::resolve_github_target;
pub use url::{convert_github_blob_to_raw, is_github_repo_homepage, is_github_web_only_path};
