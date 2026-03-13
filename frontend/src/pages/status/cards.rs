use dioxus::prelude::*;

#[component]
pub(super) fn BreakdownCard(
    title: String,
    items: Vec<(String, String)>,
    empty_message: String,
) -> Element {
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
pub(super) fn StatCard(label: String, value: String, hint: String) -> Element {
    rsx! {
        div { class: "metric-card",
            span { class: "metric-label", "{label}" }
            strong { class: "metric-value", "{value}" }
            span { class: "metric-hint", "{hint}" }
        }
    }
}
