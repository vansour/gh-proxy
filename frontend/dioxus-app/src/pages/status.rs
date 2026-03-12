use std::time::Duration;

use dioxus::prelude::*;
use gloo_timers;

use crate::api::{DashboardData, fetch_dashboard};

#[component]
pub fn Status() -> Element {
    let mut dashboard = use_signal(|| Option::<DashboardData>::None);
    let mut loading = use_signal(|| true);

    let _refresh_task = use_future(move || async move {
        loop {
            dashboard.set(Some(fetch_dashboard().await));
            loading.set(false);

            gloo_timers::future::sleep(Duration::from_secs(30)).await;
        }
    });

    rsx! {
        div { class: "page page-status",
            div { class: "status-shell",
                header { class: "status-header",
                    a { href: "/", class: "back-link", "返回首页" }
                    h1 { "服务运行状态" }
                    p { class: "status-subtitle", "页面数据来自 `/api/stats`、`/readyz` 和 `/api/config` 的实时返回。" }
                }

                if *loading.read() {
                    div { class: "loading-indicator", "加载中..." }
                } else if let Some(ref data) = *dashboard.read() {
                    StatusDashboard { data: data.clone() }
                }
            }
        }
    }
}

#[component]
fn StatusDashboard(data: DashboardData) -> Element {
    let dashboard_errors = collect_dashboard_errors(&data);
    let server = data.stats.as_ref().map(|stats| &stats.server);
    let cache = data.stats.as_ref().map(|stats| &stats.cache);
    let requests = data.stats.as_ref().map(|stats| &stats.requests);
    let errors = data.stats.as_ref().map(|stats| &stats.errors);
    let health = data.health.as_ref();
    let config = data.config.as_ref();
    let readyz_status = data.readyz_status;
    let registry_default = config
        .map(|config| config.registry.default.clone())
        .unwrap_or_else(|| "不可用".to_string());
    let registry_allowed_hosts = config
        .map(|config| format_host_list(&config.registry.allowed_hosts))
        .unwrap_or_else(|| "--".to_string());
    let registry_participates_in_readiness = config
        .map(|config| config.registry.readiness_depends_on_registry)
        .unwrap_or(false);
    let proxy_allowed_hosts = config
        .map(|config| format_host_list(&config.proxy.allowed_hosts))
        .unwrap_or_else(|| "--".to_string());
    let request_timeout_secs = config.map(|config| config.server.request_timeout_secs);
    let max_concurrent_requests = config.map(|config| config.server.max_concurrent_requests);
    let rate_limit_window_secs = config.map(|config| config.rate_limit.window_secs);
    let rate_limit_max_requests = config.map(|config| config.rate_limit.max_requests);
    let cache_strategy = config
        .map(|config| config.cache.strategy.clone())
        .unwrap_or_else(|| "--".to_string());
    let shell_editor_enabled = config.map(|config| config.shell.editor).unwrap_or(false);
    let shell_public_base_url = config
        .map(|config| config.shell.public_base_url.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "--".to_string());
    let debug_endpoints_enabled = config
        .map(|config| config.debug.endpoints_enabled)
        .unwrap_or(false);
    let registry =
        health.and_then(|health| health.checks.as_ref().map(|checks| checks.registry.clone()));
    let registry_is_healthy = registry.as_ref().map(|item| item.healthy).unwrap_or(false);
    let registry_message = registry
        .as_ref()
        .and_then(|item| item.message.as_ref())
        .cloned();
    let service_status = if let Some(health) = health {
        if !health.accepting_requests {
            "Draining"
        } else if readyz_status
            .map(|status| (200..300).contains(&status))
            .unwrap_or(false)
        {
            "Ready"
        } else if readyz_status.is_some() {
            "Degraded"
        } else {
            "Unknown"
        }
    } else {
        "Unknown"
    };
    let cache_hit_rate = cache
        .map(|cache| format_percent(cache.hit_rate))
        .unwrap_or_else(|| "--".to_string());
    let request_status_items = requests
        .map(|requests| {
            format_breakdown_items(
                &requests.by_status,
                &[
                    ("2xx", "2xx"),
                    ("3xx", "3xx"),
                    ("4xx", "4xx"),
                    ("5xx", "5xx"),
                    ("other", "other"),
                ],
            )
        })
        .unwrap_or_default();
    let request_type_items = requests
        .map(|requests| {
            format_breakdown_items(
                &requests.by_type,
                &[
                    ("github", "GitHub"),
                    ("registry", "Registry"),
                    ("api", "API"),
                    ("static", "Static"),
                    ("infra", "Infra"),
                    ("fallback", "Fallback"),
                ],
            )
        })
        .unwrap_or_default();
    let error_items = errors
        .map(|errors| {
            format_breakdown_items(
                errors,
                &[
                    ("upstream", "上游错误"),
                    ("rate_limit", "限流"),
                    ("size_exceeded", "大小超限"),
                    ("host_not_allowed", "主机拒绝"),
                    ("origin_auth_failed", "源站鉴权失败"),
                    ("method_not_allowed", "方法拒绝"),
                    ("invalid_target", "目标无效"),
                    ("timeout", "超时"),
                    ("other", "其他"),
                ],
            )
        })
        .unwrap_or_default();
    let method_items = requests
        .map(|requests| {
            format_breakdown_items(
                &requests.by_method,
                &[
                    ("GET", "GET"),
                    ("HEAD", "HEAD"),
                    ("POST", "POST"),
                    ("PUT", "PUT"),
                    ("PATCH", "PATCH"),
                    ("DELETE", "DELETE"),
                    ("OPTIONS", "OPTIONS"),
                ],
            )
        })
        .unwrap_or_default();

    rsx! {
        div {
            if !dashboard_errors.is_empty() {
                div { class: "error-banner", "{dashboard_errors.join(\" | \")}" }
            }

            section { class: "metric-grid",
                StatCard {
                    label: "服务状态".to_string(),
                    value: service_status.to_string(),
                    hint: format!(
                        "版本 {} / readyz {}",
                        health
                            .map(|health| health.version.clone())
                            .unwrap_or_else(|| "--".to_string()),
                        readyz_status
                            .map(|status| status.to_string())
                            .unwrap_or_else(|| "--".to_string())
                    )
                }
                StatCard {
                    label: "累计请求".to_string(),
                    value: server
                        .map(|server| format_number(server.total_requests))
                        .unwrap_or_else(|| "--".to_string()),
                    hint: format!(
                        "活跃请求 {}",
                        server
                            .map(|server| server.active_requests.to_string())
                            .unwrap_or_else(|| "--".to_string())
                    )
                }
                StatCard {
                    label: "累计流量".to_string(),
                    value: server
                        .map(|server| format_bytes(server.bytes_transferred))
                        .unwrap_or_else(|| "--".to_string()),
                    hint: format!(
                        "运行时长 {}",
                        server
                            .map(|server| format_duration(server.uptime_secs))
                            .unwrap_or_else(|| "--".to_string())
                    )
                }
                StatCard {
                    label: "缓存命中率".to_string(),
                    value: cache_hit_rate,
                    hint: cache
                        .map(|cache| format!("{} 条缓存对象", format_number(cache.entry_count)))
                        .unwrap_or_else(|| "缓存数据不可用".to_string())
                }
                StatCard {
                    label: "限流缓存".to_string(),
                    value: server
                        .map(|server| format_number(server.rate_limit_cache_size))
                        .unwrap_or_else(|| "--".to_string()),
                    hint: format!(
                        "状态 {}",
                        health
                            .map(|health| health.state.clone())
                            .unwrap_or_else(|| "--".to_string())
                    )
                }
            }

            section { class: "detail-grid",
                div { class: "detail-card",
                    h2 { "健康检查" }
                    if let Some(health) = health {
                        div { class: "detail-row",
                            span { class: "detail-label", "接受新请求" }
                            span {
                                class: if health.accepting_requests { "pill pill-success" } else { "pill pill-warning" },
                                if health.accepting_requests { "是" } else { "否" }
                            }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "活跃请求" }
                            span { class: "detail-value", "{health.active_requests}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "readyz 返回码" }
                            span { class: "detail-value", "{readyz_status.unwrap_or_default()}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "注册表代理" }
                            span {
                                class: if registry_is_healthy { "pill pill-success" } else { "pill pill-warning" },
                                if registry_is_healthy { "正常" } else { "降级" }
                            }
                        }
                        if let Some(message) = registry_message {
                            p { class: "detail-note", "{message}" }
                        }
                    } else {
                        p { class: "detail-note", "{data.health_error.clone().unwrap_or_else(|| \"健康数据不可用\".to_string())}" }
                    }
                }

                div { class: "detail-card",
                    h2 { "服务摘要" }
                    if let Some(server) = server {
                        div { class: "detail-row",
                            span { class: "detail-label", "Server State" }
                            span { class: "detail-value", "{health.map(|health| health.state.clone()).unwrap_or_else(|| \"--\".to_string())}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "累计请求" }
                            span { class: "detail-value", "{server.total_requests}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "累计流量" }
                            span { class: "detail-value", "{format_bytes(server.bytes_transferred)}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "运行时长" }
                            span { class: "detail-value", "{format_duration(server.uptime_secs)}" }
                        }
                    } else {
                        p { class: "detail-note", "{data.stats_error.clone().unwrap_or_else(|| \"服务摘要不可用\".to_string())}" }
                    }
                }

                div { class: "detail-card",
                    h2 { "缓存状态" }
                    if let Some(cache) = cache {
                        div { class: "detail-row",
                            span { class: "detail-label", "缓存策略" }
                            span { class: "detail-value", "{cache.strategy}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "对象数" }
                            span { class: "detail-value", "{cache.entry_count}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "占用大小" }
                            span { class: "detail-value", "{format_bytes(cache.weighted_size)}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "命中率" }
                            span { class: "detail-value", "{format_percent(cache.hit_rate)}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "命中 / 未命中" }
                            span { class: "detail-value", "{cache.hits} / {cache.misses}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "驱逐次数" }
                            span { class: "detail-value", "{cache.evictions}" }
                        }
                    } else {
                        p { class: "detail-note", "{data.stats_error.clone().unwrap_or_else(|| \"缓存数据不可用\".to_string())}" }
                    }
                }

                BreakdownCard {
                    title: "请求分类".to_string(),
                    items: request_type_items,
                    empty_message: data.stats_error.clone().unwrap_or_else(|| "暂无数据".to_string()),
                }

                BreakdownCard {
                    title: "状态码分布".to_string(),
                    items: request_status_items,
                    empty_message: data.stats_error.clone().unwrap_or_else(|| "暂无数据".to_string()),
                }

                BreakdownCard {
                    title: "请求方法".to_string(),
                    items: method_items,
                    empty_message: data.stats_error.clone().unwrap_or_else(|| "暂无数据".to_string()),
                }

                BreakdownCard {
                    title: "错误分类".to_string(),
                    items: error_items,
                    empty_message: data.stats_error.clone().unwrap_or_else(|| "暂无数据".to_string()),
                }

                div { class: "detail-card",
                    h2 { "当前配置" }
                    if config.is_some() {
                        div { class: "detail-row",
                            span { class: "detail-label", "Registry" }
                            span { class: "detail-value", "{registry_default}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "Registry 白名单" }
                            span { class: "detail-value", "{registry_allowed_hosts}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "Registry 参与 readyz" }
                            span {
                                class: if registry_participates_in_readiness { "pill pill-warning" } else { "pill pill-success" },
                                if registry_participates_in_readiness { "是" } else { "否" }
                            }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "请求超时" }
                            span { class: "detail-value", "{request_timeout_secs.unwrap_or_default()}s" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "最大并发" }
                            span { class: "detail-value", "{max_concurrent_requests.unwrap_or_default()}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "限流窗口" }
                            span { class: "detail-value", "{rate_limit_max_requests.unwrap_or_default()} / {rate_limit_window_secs.unwrap_or_default()}s" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "缓存策略" }
                            span { class: "detail-value", "{cache_strategy}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "代理上游白名单" }
                            span { class: "detail-value", "{proxy_allowed_hosts}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "Shell 编辑" }
                            span {
                                class: if shell_editor_enabled { "pill pill-success" } else { "pill pill-warning" },
                                if shell_editor_enabled { "启用" } else { "关闭" }
                            }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "Shell 对外基准 URL" }
                            span { class: "detail-value", "{shell_public_base_url}" }
                        }
                        div { class: "detail-row",
                            span { class: "detail-label", "Debug 接口" }
                            span {
                                class: if debug_endpoints_enabled { "pill pill-warning" } else { "pill pill-success" },
                                if debug_endpoints_enabled { "启用" } else { "关闭" }
                            }
                        }
                    } else {
                        p { class: "detail-note", "{data.config_error.clone().unwrap_or_else(|| \"配置数据不可用\".to_string())}" }
                    }
                }
            }
        }
    }
}

fn collect_dashboard_errors(data: &DashboardData) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(error) = &data.stats_error {
        errors.push(format!("统计接口异常: {}", error));
    }
    if let Some(error) = &data.health_error {
        errors.push(format!("健康接口异常: {}", error));
    }
    if let Some(error) = &data.config_error {
        errors.push(format!("配置接口异常: {}", error));
    }
    errors
}

#[component]
fn BreakdownCard(title: String, items: Vec<(String, String)>, empty_message: String) -> Element {
    rsx! {
        div { class: "detail-card",
            h2 { "{title}" }
            if items.is_empty() {
                p { class: "detail-note", "{empty_message}" }
            } else {
                for (label, value) in items {
                    div { class: "detail-row",
                        span { class: "detail-label", "{label}" }
                        span { class: "detail-value", "{value}" }
                    }
                }
            }
        }
    }
}

#[component]
fn StatCard(label: String, value: String, hint: String) -> Element {
    rsx! {
        div { class: "metric-card",
            span { class: "metric-label", "{label}" }
            strong { class: "metric-value", "{value}" }
            span { class: "metric-hint", "{hint}" }
        }
    }
}

const KB: u64 = 1024;
const MB: u64 = KB * 1024;
const GB_VAL: u64 = MB * 1024;

fn format_bytes(bytes: u64) -> String {
    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else if bytes < GB_VAL {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.2} GB", bytes as f64 / GB_VAL as f64)
    }
}

fn format_number(num: u64) -> String {
    if num > 1_000_000 {
        format!("{:.1}M", num as f64 / 1_000_000.0)
    } else if num > 1_000 {
        format!("{:.1}K", num as f64 / 1_000.0)
    } else {
        num.to_string()
    }
}

fn format_duration(total_secs: u64) -> String {
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

fn format_percent(value: f64) -> String {
    format!("{:.1}%", value * 100.0)
}

fn format_host_list(hosts: &[String]) -> String {
    if hosts.is_empty() {
        "--".to_string()
    } else {
        hosts.join(", ")
    }
}

fn format_breakdown_items(
    source: &std::collections::BTreeMap<String, u64>,
    labels: &[(&str, &str)],
) -> Vec<(String, String)> {
    labels
        .iter()
        .filter_map(|(key, label)| {
            let value = source.get(*key).copied().unwrap_or_default();
            if value == 0 {
                None
            } else {
                Some(((*label).to_string(), format_number(value)))
            }
        })
        .collect()
}
