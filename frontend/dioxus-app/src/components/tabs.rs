use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkFormat {
    Direct,
    GitClone,
    Wget,
    Curl,
    Docker,
}

#[component]
pub fn Tabs(
    current_format: LinkFormat,
    #[props(default = |_| {})] onchange: EventHandler<LinkFormat>,
) -> Element {
    let formats = [
        (LinkFormat::Direct, "直连链接"),
        (LinkFormat::GitClone, "Git Clone"),
        (LinkFormat::Wget, "Wget"),
        (LinkFormat::Curl, "Curl"),
        (LinkFormat::Docker, "Docker"),
    ];

    rsx! {
        nav { class: "tabs",
            {formats.iter().map(|(format, label)| {
                let format = *format;
                let is_active = current_format == format;
                rsx! {
                    button {
                        key: "{format:?}",
                        class: if is_active {
                            "tab active"
                        } else {
                            "tab"
                        },
                        "data-format": format.to_string(),
                        onclick: move |_| onchange.call(format),
                        "{label}"
                    }
                }
            })}
        }
    }
}

impl LinkFormat {
    pub fn to_string(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::GitClone => "git",
            Self::Wget => "wget",
            Self::Curl => "curl",
            Self::Docker => "docker",
        }
    }
}
