use std::sync::OnceLock;

use web_sys::Url;

use super::allowed_hosts::{is_allowed_host, looks_like_allowed_host_prefix};

static DUPLICATE_PROXY_PREFIX_REGEX: OnceLock<Result<regex::Regex, regex::Error>> = OnceLock::new();

pub(super) fn normalize_github_resource(
    raw_input: &str,
    allowed_hosts: &[String],
) -> Result<Url, String> {
    let mut raw_url = clean_github_url(raw_input);
    if raw_url.is_empty() {
        return Err(github_input_help());
    }

    if !raw_url.starts_with("http://") && !raw_url.starts_with("https://") {
        if looks_like_allowed_host_prefix(&raw_url, allowed_hosts) {
            raw_url = format!("https://{}", raw_url);
        } else if is_allowed_host("github.com", allowed_hosts)
            && raw_url
                .split('/')
                .filter(|segment| !segment.is_empty())
                .count()
                >= 4
        {
            raw_url = format!("https://github.com/{}", raw_url.trim_start_matches('/'));
        } else {
            return Err(github_input_help());
        }
    }

    let parsed = Url::new(&raw_url).map_err(|_| github_input_help())?;
    let host = parsed.hostname().to_lowercase();

    if !is_allowed_host(&host, allowed_hosts) {
        return Err(github_input_help());
    }

    let path = parsed.pathname();
    let path_segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count();
    let github_path_ok = path.contains("/blob/")
        || path.contains("/raw/")
        || path.contains("/zipball/")
        || path.contains("/tarball/")
        || path.contains("/archive/")
        || path.contains("/releases/download/")
        || (path.contains("/releases/") && path.contains("/download/"));

    match host.as_str() {
        "github.com" => {
            if !github_path_ok || path_segments < 4 {
                return Err(github_input_help());
            }
        }
        "raw.githubusercontent.com" | "codeload.github.com" => {
            if path_segments < 4 {
                return Err(github_input_help());
            }
        }
        _ => {}
    }

    Ok(parsed)
}

pub(super) fn clean_github_url(url: &str) -> String {
    let trimmed = url.trim();
    let regex = DUPLICATE_PROXY_PREFIX_REGEX
        .get_or_init(|| regex::Regex::new(r"^https?://[^/]+/(https?://)"));

    match regex {
        Ok(re) => re.replace(trimmed, "$1").to_string(),
        Err(_) => trimmed.to_string(),
    }
}

fn github_input_help() -> String {
    "请输入可代理的 GitHub 或上游资源地址，例如 https://github.com/owner/repo/blob/main/file.txt"
        .to_string()
}
