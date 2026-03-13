use dioxus::prelude::*;

#[component]
pub fn Input(
    #[props(default = String::new())] value: String,
    placeholder: String,
    #[props(default = |_| {})] oninput: EventHandler<FormEvent>,
    #[props(default = |_| {})] onkeydown: EventHandler<KeyboardEvent>,
) -> Element {
    rsx! {
        div { class: "input-group",
            input {
                r#type: "text",
                class: "input-field",
                placeholder: "{placeholder}",
                value: "{value}",
                autocomplete: "off",
                oninput,
                onkeydown
            }
        }
    }
}
