use clap::ValueEnum;
use serde::Deserialize;
use strum::{Display, EnumString};

#[derive(Debug, serde::Deserialize, Default, Clone, EnumString, Display, Copy, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SortingMethod {
    #[default]
    /// Sort by name
    Name,
    /// Sort by size
    Size,
    /// Sort by last modification date (natural sort: follows alphanumerical order)
    Date,
}

/// Available sorting orders
#[derive(Debug, Deserialize, Default, Clone, EnumString, Display, Copy, ValueEnum)]
pub enum SortingOrder {
    /// Ascending order
    #[serde(alias = "asc")]
    #[strum(serialize = "asc")]
    Asc,
    /// Descending order
    #[default]
    #[serde(alias = "desc")]
    #[strum(serialize = "desc")]
    Desc,
}
