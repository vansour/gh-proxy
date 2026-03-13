mod api;
mod components;
mod pages;

pub use components::*;
pub use pages::*;

use dioxus::prelude::*;

const APP_CSS: &str = include_str!("styles.css");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppPage {
    Home,
    Status,
}

fn current_page() -> AppPage {
    let path = web_sys::window()
        .and_then(|window| window.location().pathname().ok())
        .unwrap_or_else(|| "/".to_string());

    match path.as_str() {
        "/status" => AppPage::Status,
        _ => AppPage::Home,
    }
}

pub fn app() -> Element {
    let page = current_page();

    rsx! {
        style { "{APP_CSS}" }
        div { id: "app",
            match page {
                AppPage::Home => rsx! { Home {} },
                AppPage::Status => rsx! { Status {} },
            }
        }
    }
}
