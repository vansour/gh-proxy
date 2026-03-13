use dioxus::prelude::*;

#[component]
pub fn PrimaryButton(children: Element, disabled: bool, onclick: EventHandler<()>) -> Element {
    rsx! {
        button {
            class: "primary-btn",
            disabled: "{disabled}",
            onclick: move |_| onclick.call(()),
            {children}
        }
    }
}

#[component]
pub fn SecondaryButton(children: Element, disabled: bool, onclick: EventHandler<()>) -> Element {
    rsx! {
        button {
            class: "secondary-btn",
            disabled: "{disabled}",
            onclick: move |_| onclick.call(()),
            {children}
        }
    }
}
