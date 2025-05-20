use axum::{extract::State, http::StatusCode, response::IntoResponse, response::Response};
use clap::ValueEnum;
use serde::Deserialize;
use std::time::SystemTime;
use strum::{Display, EnumString};
use tokio::fs::File;
use tokio_util::io::ReaderStream;

use crate::{ArchiveMethod, MiniserveConfig};

/// "percent-encode sets" as defined by WHATWG specs:
/// https://url.spec.whatwg.org/#percent-encoded-bytes
pub mod percent_encode_sets {
    use percent_encoding::{AsciiSet, CONTROLS};
    pub const QUERY: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>');
    pub const PATH: &AsciiSet = &QUERY.add(b'?').add(b'`').add(b'{').add(b'}');
    pub const USERINFO: &AsciiSet = &PATH
        .add(b'/')
        .add(b':')
        .add(b';')
        .add(b'=')
        .add(b'@')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'^')
        .add(b'|');
    pub const COMPONENT: &AsciiSet = &USERINFO.add(b'$').add(b'%').add(b'&').add(b'+').add(b',');
}

/// Query parameters used by listing APIs
#[derive(Deserialize, Default)]
pub struct ListingQueryParameters {
    pub sort: Option<SortingMethod>,
    pub order: Option<SortingOrder>,
    pub raw: Option<bool>,
    download: Option<ArchiveMethod>,
}

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

/// Possible entry types
#[derive(PartialEq, Clone, Display, Eq)]
#[strum(serialize_all = "snake_case")]
pub enum EntryType {
    /// Entry is a directory
    Directory,

    /// Entry is a file
    File,
}

/// Entry
pub struct Entry {
    /// Name of the entry
    pub name: String,

    /// Type of the entry
    pub entry_type: EntryType,

    /// URL of the entry
    pub link: String,

    /// Size in byte of the entry. Only available for EntryType::File
    pub size: Option<bytesize::ByteSize>,

    /// Last modification date
    pub last_modification_date: Option<SystemTime>,

    /// Path of symlink pointed to
    pub symlink_info: Option<String>,
}

impl Entry {
    fn new(
        name: String,
        entry_type: EntryType,
        link: String,
        size: Option<bytesize::ByteSize>,
        last_modification_date: Option<SystemTime>,
        symlink_info: Option<String>,
    ) -> Self {
        Self {
            name,
            entry_type,
            link,
            size,
            last_modification_date,
            symlink_info,
        }
    }

    /// Returns whether the entry is a directory
    pub fn is_dir(&self) -> bool {
        self.entry_type == EntryType::Directory
    }

    /// Returns whether the entry is a file
    pub fn is_file(&self) -> bool {
        self.entry_type == EntryType::File
    }
}

/// One entry in the path to the listed directory
pub struct Breadcrumb {
    /// Name of directory
    pub name: String,

    /// Link to get to directory, relative to listed directory
    pub link: String,
}

impl Breadcrumb {
    fn new(name: String, link: String) -> Self {
        Self { name, link }
    }
}

pub async fn file_handler(
    State(conf): State<MiniserveConfig>,
) -> Result<Response, (StatusCode, String)> {
    let file = File::open(&conf.path)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, format!("File not found: {}", e)))?;
    let stream = ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    Ok(body.into_response())
}
