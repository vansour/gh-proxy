use dioxus::prelude::*;

#[component]
pub fn Toast(visible: bool, message: String) -> Element {
    if !visible {
        return rsx! {};
    }

    rsx! {
        div {
            class: "toast visible",
            role: "status",
            "aria-live": "polite",
            "{message}"
        }
    }
}
