use clap::ValueEnum;
use strum::Display;

#[derive(Debug, Clone, ValueEnum, Display)]
pub enum ThemeSlug {
    #[strum(serialize = "squirrel")]
    Squirrel,
    #[strum(serialize = "archlinux")]
    Archlinux,
    #[strum(serialize = "zenburn")]
    Zenburn,
    #[strum(serialize = "monokai")]
    Monokai,
}

impl ThemeSlug {
    pub fn css(&self) -> &str {
        match self {
            ThemeSlug::Squirrel => grass::include!("data/themes/squirrel.scss"),
            ThemeSlug::Archlinux => grass::include!("data/themes/archlinux.scss"),
            ThemeSlug::Zenburn => grass::include!("data/themes/zenburn.scss"),
            ThemeSlug::Monokai => grass::include!("data/themes/monokai.scss"),
        }
    }

    pub fn css_dark(&self) -> String {
        format!("@media (prefers-color-scheme: dark) {{\n{}}}", self.css())
    }
}
