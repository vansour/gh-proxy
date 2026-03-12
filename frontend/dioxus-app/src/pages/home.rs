use std::sync::OnceLock;
use std::time::Duration;

use dioxus::prelude::*;
use gloo_timers;
use wasm_bindgen_futures::JsFuture;
use web_sys::window;

use crate::api::fetch_config;
use crate::components::{LinkFormat, PrimaryButton, SecondaryButton, Tabs};

#[derive(Clone, Debug)]
struct GeneratedOutput {
    text: String,
    is_url: bool,
}

static DUPLICATE_PROXY_PREFIX_REGEX: OnceLock<Result<regex::Regex, regex::Error>> = OnceLock::new();
const DEFAULT_ALLOWED_HOSTS: [&str; 4] = [
    "github.com",
    "*.github.com",
    "githubusercontent.com",
    "*.githubusercontent.com",
];

#[component]
pub fn Home() -> Element {
    let mut input_value = use_signal(String::new);
    let current_format = use_signal(|| LinkFormat::Direct);
    let allowed_hosts = use_signal(default_allowed_hosts);
    let input_error = use_signal(String::new);
    let output = use_signal(String::new);
    let show_result = use_signal(|| false);
    let open_in_browser_enabled = use_signal(|| false);
    let toast_visible = use_signal(|| false);
    let toast_message = use_signal(|| "已成功复制".to_string());

    let _config_task = use_future(move || {
        let mut allowed_hosts = allowed_hosts;
        let input_value = input_value;
        let current_format = current_format;
        let output = output;
        let show_result = show_result;
        let open_in_browser_enabled = open_in_browser_enabled;
        let input_error = input_error;

        async move {
            if let Ok(config) = fetch_config().await {
                let hosts = config.proxy.allowed_hosts;
                allowed_hosts.set(hosts.clone());

                let raw_url = input_value.read().to_string();
                if !raw_url.trim().is_empty() {
                    apply_output_state(
                        &raw_url,
                        *current_format.read(),
                        &hosts,
                        output,
                        show_result,
                        open_in_browser_enabled,
                        input_error,
                    );
                }
            }
        }
    });

    let apply_output = {
        let output = output;
        let show_result = show_result;
        let open_in_browser_enabled = open_in_browser_enabled;
        let input_error = input_error;
        let allowed_hosts = allowed_hosts;

        move |format_override: Option<LinkFormat>| {
            let raw_url = input_value.read().to_string();
            let format = format_override.unwrap_or(*current_format.read());
            let allowed_hosts = allowed_hosts.read().clone();

            apply_output_state(
                &raw_url,
                format,
                &allowed_hosts,
                output,
                show_result,
                open_in_browser_enabled,
                input_error,
            );
        }
    };

    let mut on_generate = {
        let apply_output = apply_output;
        let input_value = input_value;
        let mut output = output;
        let mut show_result = show_result;
        let mut open_in_browser_enabled = open_in_browser_enabled;
        let mut input_error = input_error;

        move |_| {
            if input_value.read().trim().is_empty() {
                output.set(String::new());
                open_in_browser_enabled.set(false);
                show_result.set(false);
                input_error.set(String::new());
                return;
            }

            apply_output(None);
        }
    };

    let on_tab_change = {
        let apply_output = apply_output;
        let mut current_format = current_format;
        let input_value = input_value;

        move |format| {
            current_format.set(format);
            if !input_value.read().trim().is_empty() {
                apply_output(Some(format));
            }
        }
    };

    let on_copy = {
        move |_| {
            let text = output.read().clone();
            let mut toast_message = toast_message;
            let mut toast_visible = toast_visible;

            spawn(async move {
                match copy_text(&text).await {
                    Ok(()) => toast_message.set("已复制到剪贴板".to_string()),
                    Err(_) => toast_message.set("复制失败，请手动复制".to_string()),
                }

                toast_visible.set(true);
                gloo_timers::future::sleep(Duration::from_secs(2)).await;
                toast_visible.set(false);
            });
        }
    };

    let on_open = {
        move |_| {
            if !*open_in_browser_enabled.read() {
                return;
            }

            let url = output.read().clone();
            if !url.starts_with("http") {
                return;
            }

            if let Some(browser) = window() {
                let _ = browser.open_with_url_and_target(&url, "_blank");
            }
        }
    };

    rsx! {
        div { class: "page page-home",
            div { class: "app-container",
                main { class: "mica-card",
                    header {
                        div { class: "logo",
                            h1 { "GH-Proxy" }
                        }
                        p { class: "hero-copy", "把 GitHub 文件或发布资源地址转换为当前代理入口下的可访问链接。" }
                    }

                    div { class: "input-section",
                        Tabs {
                            current_format: *current_format.read(),
                            onchange: on_tab_change
                        }

                        input {
                            r#type: "text",
                            class: "input-field",
                            placeholder: "{input_placeholder(*current_format.read())}",
                            value: "{input_value.read()}",
                            autocomplete: "off",
                            oninput: move |event| input_value.set(event.value()),
                            onkeydown: move |event| {
                                if event.key() == Key::Enter {
                                    on_generate(());
                                }
                            }
                        }

                        if !input_error.read().is_empty() {
                            p { class: "input-error", "{input_error.read()}" }
                        }

                        PrimaryButton {
                            disabled: false,
                            onclick: on_generate,
                            "获取加速地址"
                        }
                    }

                    if *show_result.read() {
                        section { class: "result-area visible",
                            div { class: "code-display", "{output.read()}" }
                            div { class: "action-row",
                                SecondaryButton {
                                    disabled: !*open_in_browser_enabled.read(),
                                    onclick: on_open,
                                    "浏览器打开"
                                }
                                SecondaryButton {
                                    disabled: false,
                                    onclick: on_copy,
                                    "点击复制"
                                }
                            }
                        }
                    }
                }
            }

            if *toast_visible.read() {
                div { class: "toast visible", "{toast_message.read()}" }
            }
        }
    }
}

fn apply_output_state(
    raw_input: &str,
    format: LinkFormat,
    allowed_hosts: &[String],
    mut output: Signal<String>,
    mut show_result: Signal<bool>,
    mut open_in_browser_enabled: Signal<bool>,
    mut input_error: Signal<String>,
) {
    let host = browser_host();
    match build_output(raw_input, format, allowed_hosts, &host) {
        Ok(result) => {
            output.set(result.text);
            open_in_browser_enabled.set(result.is_url);
            show_result.set(true);
            input_error.set(String::new());
        }
        Err(error) => {
            output.set(String::new());
            open_in_browser_enabled.set(false);
            show_result.set(false);
            input_error.set(error);
        }
    }
}

fn build_output(
    raw_input: &str,
    format: LinkFormat,
    allowed_hosts: &[String],
    host: &str,
) -> Result<GeneratedOutput, String> {
    if format == LinkFormat::Docker {
        return build_docker_output(raw_input, host);
    }

    let parsed = normalize_github_resource(raw_input, allowed_hosts)?;
    let origin = browser_origin();
    let proxy_link = format!(
        "{}/{}{}{}{}",
        origin,
        parsed.hostname(),
        parsed.pathname(),
        parsed.search(),
        parsed.hash()
    );

    let text = match format {
        LinkFormat::Direct => proxy_link.clone(),
        LinkFormat::GitClone => format!("git clone {}", proxy_link),
        LinkFormat::Wget => format!("wget \"{}\"", proxy_link),
        LinkFormat::Curl => format!("curl -O \"{}\"", proxy_link),
        LinkFormat::Docker => unreachable!(),
    };

    Ok(GeneratedOutput {
        text,
        is_url: format == LinkFormat::Direct,
    })
}

fn build_docker_output(raw_input: &str, host: &str) -> Result<GeneratedOutput, String> {
    let image = raw_input.trim();
    if image.is_empty() {
        return Err("Docker 模式请输入镜像名，例如 library/nginx:latest".to_string());
    }
    if image.contains(char::is_whitespace)
        || image.starts_with("http://")
        || image.starts_with("https://")
        || image.contains("github.com")
    {
        return Err("Docker 模式只接受镜像名，例如 library/nginx:latest".to_string());
    }

    Ok(GeneratedOutput {
        text: format!("docker pull {}/{}", host, image.trim_matches('/')),
        is_url: false,
    })
}

fn normalize_github_resource(
    raw_input: &str,
    allowed_hosts: &[String],
) -> Result<web_sys::Url, String> {
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

    let parsed = web_sys::Url::new(&raw_url).map_err(|_| github_input_help())?;
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

fn default_allowed_hosts() -> Vec<String> {
    DEFAULT_ALLOWED_HOSTS
        .iter()
        .map(|host| (*host).to_string())
        .collect()
}

fn is_allowed_host(host: &str, allowed_hosts: &[String]) -> bool {
    let host = host.trim().trim_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }

    allowed_hosts
        .iter()
        .filter_map(|pattern| parse_allowed_host_pattern(pattern))
        .any(|pattern| pattern.matches(&host))
}

fn looks_like_allowed_host_prefix(input: &str, allowed_hosts: &[String]) -> bool {
    let trimmed = input.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return false;
    }

    let candidate = trimmed.split(['/', '?', '#']).next().unwrap_or_default();
    let host = if candidate.starts_with('[') {
        candidate
            .strip_prefix('[')
            .and_then(|value| value.split_once(']'))
            .map(|(value, _)| value)
            .unwrap_or(candidate)
    } else {
        candidate
            .split_once(':')
            .map(|(value, _)| value)
            .unwrap_or(candidate)
    };

    is_allowed_host(host, allowed_hosts)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AllowedHostKind {
    Exact,
    Suffix,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AllowedHostPattern {
    value: String,
    kind: AllowedHostKind,
    suffix: Option<String>,
}

impl AllowedHostPattern {
    fn matches(&self, host: &str) -> bool {
        match self.kind {
            AllowedHostKind::Exact => host == self.value,
            AllowedHostKind::Suffix => {
                self.suffix
                    .as_ref()
                    .map(|suffix| host.ends_with(suffix))
                    .unwrap_or(false)
            }
        }
    }
}

fn parse_allowed_host_pattern(raw: &str) -> Option<AllowedHostPattern> {
    let mut pattern = raw.trim();
    if pattern.is_empty() {
        return None;
    }

    if let Some((_, suffix)) = pattern.split_once("://") {
        pattern = suffix;
    }
    if let Some((host, _)) = pattern.split_once('/') {
        pattern = host;
    }
    if pattern.starts_with('[') {
        let closing = pattern.find(']')?;
        pattern = &pattern[1..closing];
    } else if let Some((host, _)) = pattern.split_once(':') {
        pattern = host;
    }

    pattern = pattern.trim();
    let is_suffix = pattern.starts_with("*.") || pattern.starts_with('.');
    let host = pattern
        .strip_prefix("*.")
        .or_else(|| pattern.strip_prefix('.'))
        .unwrap_or(pattern)
        .trim_matches('.');
    if host.is_empty() || host.contains('*') {
        return None;
    }

    let value = host.to_ascii_lowercase();
    let kind = if is_suffix {
        AllowedHostKind::Suffix
    } else {
        AllowedHostKind::Exact
    };
    let suffix = is_suffix.then(|| format!(".{}", value));
    Some(AllowedHostPattern {
        value,
        kind,
        suffix,
    })
}

fn input_placeholder(format: LinkFormat) -> &'static str {
    match format {
        LinkFormat::Docker => "输入镜像名，例如 library/nginx:latest",
        _ => "输入 GitHub 文件 URL、raw URL 或 release 下载地址...",
    }
}

fn github_input_help() -> String {
    "请输入可代理的 GitHub 或上游资源地址，例如 https://github.com/owner/repo/blob/main/file.txt"
        .to_string()
}

fn browser_origin() -> String {
    window()
        .and_then(|browser| browser.location().origin().ok())
        .unwrap_or_else(|| "http://localhost:8080".to_string())
}

fn browser_host() -> String {
    window()
        .and_then(|browser| browser.location().host().ok())
        .unwrap_or_else(|| "localhost:8080".to_string())
}

fn clean_github_url(url: &str) -> String {
    let trimmed = url.trim();
    let regex = DUPLICATE_PROXY_PREFIX_REGEX
        .get_or_init(|| regex::Regex::new(r"^https?://[^/]+/(https?://)"));

    match regex {
        Ok(re) => re.replace(trimmed, "$1").to_string(),
        Err(_) => trimmed.to_string(),
    }
}

async fn copy_text(text: &str) -> Result<(), String> {
    let browser = web_sys::window().ok_or("No window")?;
    let navigator = browser.navigator();
    let clipboard = navigator.clipboard();
    let promise = clipboard.write_text(text);

    JsFuture::from(promise)
        .await
        .map_err(|event| format!("Clipboard write failed: {:?}", event))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        clean_github_url, default_allowed_hosts, is_allowed_host, looks_like_allowed_host_prefix,
    };

    #[test]
    fn clean_github_url_strips_nested_proxy_prefix() {
        assert_eq!(
            clean_github_url(
                "https://proxy.example/https://github.com/owner/repo/blob/main/file.txt"
            ),
            "https://github.com/owner/repo/blob/main/file.txt"
        );
    }

    #[test]
    fn clean_github_url_preserves_plain_github_url() {
        let url = "https://github.com/owner/repo/blob/main/file.txt";
        assert_eq!(clean_github_url(url), url);
    }

    #[test]
    fn allowed_hosts_match_exact_and_suffix_patterns() {
        let allowed_hosts = vec![
            "github.com".to_string(),
            "*.githubusercontent.com".to_string(),
        ];

        assert!(is_allowed_host("github.com", &allowed_hosts));
        assert!(is_allowed_host("raw.githubusercontent.com", &allowed_hosts));
        assert!(is_allowed_host(
            "objects.githubusercontent.com",
            &allowed_hosts
        ));
        assert!(!is_allowed_host("example.com", &allowed_hosts));
        // githubusercontent.com should not match *.githubusercontent.com exactly
        // because we haven't added "githubusercontent.com" to the list.
        assert!(!is_allowed_host("githubusercontent.com", &allowed_hosts));
    }

    #[test]
    fn test_parse_allowed_host_pattern() {
        use super::parse_allowed_host_pattern;

        let p1 = parse_allowed_host_pattern("github.com").unwrap();
        assert_eq!(p1.value, "github.com");
        assert_eq!(p1.suffix, None);

        let p2 = parse_allowed_host_pattern("*.githubusercontent.com").unwrap();
        assert_eq!(p2.value, "githubusercontent.com");
        assert_eq!(p2.suffix, Some(".githubusercontent.com".to_string()));

        let p3 = parse_allowed_host_pattern("  HTTPS://GITHUB.COM/  ").unwrap();
        assert_eq!(p3.value, "github.com");

        assert!(parse_allowed_host_pattern("  ").is_none());
        assert!(parse_allowed_host_pattern("*").is_none());
    }

    #[test]
    fn test_build_docker_output() {
        use super::build_docker_output;

        let res = build_docker_output("library/nginx:latest", "proxy.com").unwrap();
        assert!(res.text.contains("docker pull proxy.com/library/nginx:latest"));
        assert!(!res.is_url);

        let err = build_docker_output("  ", "proxy.com").unwrap_err();
        assert!(err.contains("请输入镜像名"));

        let err2 = build_docker_output("https://github.com/owner/repo", "proxy.com").unwrap_err();
        assert!(err2.contains("只接受镜像名"));
    }

    #[test]
    fn allowed_host_prefix_detects_scheme_less_input() {
        let allowed_hosts = default_allowed_hosts();

        assert!(looks_like_allowed_host_prefix(
            "raw.githubusercontent.com/owner/repo/main/file.txt",
            &allowed_hosts
        ));
        assert!(!looks_like_allowed_host_prefix(
            "owner/repo/blob/main/file.txt",
            &allowed_hosts
        ));
    }
}
