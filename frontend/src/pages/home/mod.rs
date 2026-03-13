mod allowed_hosts;
mod normalize;
mod output;

use std::time::Duration;

use dioxus::prelude::*;
use gloo_timers;
use wasm_bindgen_futures::JsFuture;
use web_sys::window;

use crate::api::fetch_config;
use crate::components::{Input, LinkFormat, PrimaryButton, SecondaryButton, Tabs, Toast};

use self::allowed_hosts::default_allowed_hosts;
use self::output::build_output;

#[cfg(test)]
use self::allowed_hosts::{
    is_allowed_host, looks_like_allowed_host_prefix, parse_allowed_host_pattern,
};
#[cfg(test)]
use self::normalize::clean_github_url;
#[cfg(test)]
use self::output::build_docker_output;

#[component]
pub fn Home() -> Element {
    let mut input_value = use_signal(String::new);
    let mut current_format = use_signal(|| LinkFormat::Direct);
    let mut allowed_hosts = use_signal(default_allowed_hosts);
    let mut input_error = use_signal(String::new);
    let mut output = use_signal(String::new);
    let mut show_result = use_signal(|| false);
    let mut open_in_browser_enabled = use_signal(|| false);
    let toast_visible = use_signal(|| false);
    let toast_message = use_signal(|| "已成功复制".to_string());

    let _config_task = use_future(move || async move {
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
    });

    let apply_output = move |format_override: Option<LinkFormat>| {
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
    };

    let mut on_generate = move |_| {
        if input_value.read().trim().is_empty() {
            output.set(String::new());
            open_in_browser_enabled.set(false);
            show_result.set(false);
            input_error.set(String::new());
            return;
        }

        apply_output(None);
    };

    let on_tab_change = move |format| {
        current_format.set(format);
        if !input_value.read().trim().is_empty() {
            apply_output(Some(format));
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

                        Input {
                            value: input_value.read().to_string(),
                            placeholder: input_placeholder(*current_format.read()).to_string(),
                            oninput: move |event: FormEvent| input_value.set(event.value()),
                            onkeydown: move |event: KeyboardEvent| {
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

            Toast {
                visible: *toast_visible.read(),
                message: toast_message.read().to_string(),
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
    let origin = browser_origin();
    let host = browser_host();

    match build_output(raw_input, format, allowed_hosts, &origin, &host) {
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

fn input_placeholder(format: LinkFormat) -> &'static str {
    match format {
        LinkFormat::Docker => "输入镜像名，例如 library/nginx:latest",
        _ => "输入 GitHub 文件 URL、raw URL 或 release 下载地址...",
    }
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
        build_docker_output, clean_github_url, default_allowed_hosts, is_allowed_host,
        looks_like_allowed_host_prefix, parse_allowed_host_pattern,
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
        let allowed_hosts = vec!["*.githubusercontent.com".to_string()];

        assert!(is_allowed_host("githubusercontent.com", &allowed_hosts));
        assert!(is_allowed_host("raw.githubusercontent.com", &allowed_hosts));
        assert!(is_allowed_host(
            "objects.githubusercontent.com",
            &allowed_hosts
        ));
        assert!(!is_allowed_host("example.com", &allowed_hosts));
    }

    #[test]
    fn test_parse_allowed_host_pattern() {
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
        let res = build_docker_output("library/nginx:latest", "proxy.com").unwrap();
        assert!(
            res.text
                .contains("docker pull proxy.com/library/nginx:latest")
        );
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
