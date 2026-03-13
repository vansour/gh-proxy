use crate::api::{CacheKindStats, DashboardData};
use std::collections::BTreeMap;

const KB: u64 = 1024;
const MB: u64 = KB * 1024;
const GB_VAL: u64 = MB * 1024;

pub(super) fn collect_dashboard_errors(data: &DashboardData) -> Vec<String> {
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

pub(super) fn format_bytes(bytes: u64) -> String {
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

pub(super) fn format_number(num: u64) -> String {
    if num > 1_000_000 {
        format!("{:.1}M", num as f64 / 1_000_000.0)
    } else if num > 1_000 {
        format!("{:.1}K", num as f64 / 1_000.0)
    } else {
        num.to_string()
    }
}

pub(super) fn format_duration(total_secs: u64) -> String {
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

pub(super) fn format_percent(value: f64) -> String {
    format!("{:.1}%", value * 100.0)
}

pub(super) fn format_host_list(hosts: &[String]) -> String {
    if hosts.is_empty() {
        "--".to_string()
    } else {
        hosts.join(", ")
    }
}

pub(super) fn format_breakdown_items(
    source: &BTreeMap<String, u64>,
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

pub(super) fn format_cache_kind_items(
    source: &BTreeMap<String, CacheKindStats>,
) -> Vec<(String, String)> {
    let mut items = Vec::new();

    for kind in ["gh", "manifest", "blob", "generic"] {
        if let Some(stats) = source.get(kind) {
            if stats.hits == 0 && stats.misses == 0 {
                continue;
            }

            items.push((
                cache_kind_label(kind).to_string(),
                format!(
                    "命中 {} / 未命中 {}",
                    format_number(stats.hits),
                    format_number(stats.misses)
                ),
            ));
        }
    }

    for (kind, stats) in source {
        if ["gh", "manifest", "blob", "generic"].contains(&kind.as_str())
            || (stats.hits == 0 && stats.misses == 0)
        {
            continue;
        }

        items.push((
            cache_kind_label(kind).to_string(),
            format!(
                "命中 {} / 未命中 {}",
                format_number(stats.hits),
                format_number(stats.misses)
            ),
        ));
    }

    items
}

fn cache_kind_label(kind: &str) -> &str {
    match kind {
        "gh" => "GitHub",
        "manifest" => "Manifest",
        "blob" => "Blob",
        "generic" => "Generic",
        _ => kind,
    }
}
