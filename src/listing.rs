use crate::{ArchiveMethod, CurrentUser, MiniserveConfig, render};
use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use clap::ValueEnum;
use futures::channel::mpsc;
use percent_encode_sets::COMPONENT;
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use regex::Regex;
use serde::Deserialize;
use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};
use strum::{Display, EnumString};
use tokio::fs::File;
use tokio_util::io::ReaderStream;

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

/// A directory; responds with the generated directory listing.
#[derive(Debug)]
pub struct Directory {
    /// Base directory.
    pub base: PathBuf,

    /// Path of subdirectory to generate listing for.
    pub path: PathBuf,
}

impl Directory {
    /// Create a new directory
    pub fn new(base: PathBuf, path: PathBuf) -> Directory {
        Directory { base, path }
    }

    /// Is this entry visible from this directory?
    pub async fn is_visible(&self, entry: &tokio::fs::DirEntry) -> bool {
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with('.') {
                return false;
            }
        }
        if let Ok(ref md) = entry.metadata().await {
            let ft = md.file_type();
            return ft.is_dir() || ft.is_file() || ft.is_symlink();
        } else {
            false
        }
    }
}

pub async fn directory_listing(
    uri: Uri,
    headers: HeaderMap,
    Query(query_params): Query<ListingQueryParameters>,
    State(config): State<Arc<MiniserveConfig>>,
) -> Response {
    let current_user: Option<CurrentUser> = None; // 从请求中提取用户信息

    if config.disable_indexing {
        return (StatusCode::NOT_FOUND, "File not found.").into_response();
    }

    let serve_path = uri.path();
    let base = Path::new(serve_path);
    let random_route_abs = format!("/{}", config.route_prefix);

    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let abs_uri = format!(
        "{}://{}{}",
        scheme,
        host,
        uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(serve_path)
    );
    let is_root = base.parent().is_none() || Path::new(&serve_path) == Path::new(&random_route_abs);

    let encoded_dir = match base.strip_prefix(&random_route_abs) {
        Ok(c_d) => Path::new("/").join(c_d),
        Err(_) => base.to_path_buf(),
    }
    .display()
    .to_string();

    // 构建面包屑导航
    let breadcrumbs = {
        let title = config.title.clone().unwrap_or_else(|| host.to_string());

        let decoded = percent_decode_str(&encoded_dir).decode_utf8_lossy();

        let mut res: Vec<Breadcrumb> = Vec::new();
        let mut link_accumulator = format!("{}/", &config.route_prefix);
        let mut components = Path::new(&*decoded).components().peekable();

        while let Some(c) = components.next() {
            let name;

            match c {
                Component::RootDir => {
                    name = title.clone();
                }
                Component::Normal(s) => {
                    name = s.to_string_lossy().to_string();
                    link_accumulator
                        .push_str(&(utf8_percent_encode(&name, COMPONENT).to_string() + "/"));
                }
                _ => name = "".to_string(),
            };

            res.push(Breadcrumb::new(
                name,
                if components.peek().is_some() {
                    link_accumulator.clone()
                } else {
                    ".".to_string()
                },
            ));
        }
        res
    };

    // 创建目录对象
    let dir = Directory {
        base: PathBuf::from(serve_path),
        path: PathBuf::from(serve_path),
    };

    let mut entries: Vec<Entry> = Vec::new();
    let mut readme: Option<(String, String)> = None;
    let readme_rx: Regex = Regex::new("^readme([.](md|txt))?$").unwrap();

    // 读取目录条目
    let read_dir_result = tokio::fs::read_dir(&dir.path).await;
    let mut read_dir = match read_dir_result {
        Ok(rd) => rd,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read directory: {}", err),
            )
                .into_response();
        }
    };

    while let Some(entry_result) = read_dir.next_entry().await.transpose() {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        if dir.is_visible(&entry).await || config.show_hidden {
            // show file url as relative to static path
            let file_name = entry.file_name().to_string_lossy().to_string();
            let (is_symlink, metadata) = match entry.metadata().await {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    // for symlinks, get the metadata of the original file
                    (true, std::fs::metadata(entry.path()))
                }
                res => (false, res),
            };
            let symlink_dest = (is_symlink && config.show_symlink_info)
                .then(|| entry.path())
                .and_then(|path| std::fs::read_link(path).ok())
                .map(|path| path.to_string_lossy().into_owned());
            let file_url = base
                .join(utf8_percent_encode(&file_name, COMPONENT).to_string())
                .to_string_lossy()
                .to_string();

            // if file is a directory, add '/' to the end of the name
            if let Ok(metadata) = metadata {
                if config.no_symlinks && is_symlink {
                    continue;
                }
                let last_modification_date = metadata.modified().ok();

                if metadata.is_dir() {
                    entries.push(Entry::new(
                        file_name,
                        EntryType::Directory,
                        file_url,
                        None,
                        last_modification_date,
                        symlink_dest,
                    ));
                } else if metadata.is_file() {
                    entries.push(Entry::new(
                        file_name.clone(),
                        EntryType::File,
                        file_url,
                        Some(bytesize::ByteSize::b(metadata.len())),
                        last_modification_date,
                        symlink_dest,
                    ));
                    if config.readme && readme_rx.is_match(&file_name.to_lowercase()) {
                        let ext = file_name.split('.').next_back().unwrap().to_lowercase();
                        if let Ok(content) = std::fs::read_to_string(entry.path()) {
                            readme = Some((
                                file_name.to_string(),
                                if ext == "md" {
                                    // 使用 comrak 或其他 markdown 处理器
                                    markdown_to_html(&content, &comrak::ComrakOptions::default())
                                } else {
                                    format!("<pre>{}</pre>", content)
                                },
                            ));
                        }
                    }
                }
            } else {
                continue;
            }
        }
    }

    // 排序逻辑
    match query_params.sort.unwrap_or(config.default_sorting_method) {
        SortingMethod::Name => entries.sort_by(|e1, e2| {
            alphanumeric_sort::compare_str(e1.name.to_lowercase(), e2.name.to_lowercase())
        }),
        SortingMethod::Size => entries.sort_by(|e1, e2| {
            // If we can't get the size of the entry (directory for instance)
            // let's consider it's 0b
            e2.size
                .unwrap_or_else(|| bytesize::ByteSize::b(0))
                .cmp(&e1.size.unwrap_or_else(|| bytesize::ByteSize::b(0)))
        }),
        SortingMethod::Date => entries.sort_by(|e1, e2| {
            // If, for some reason, we can't get the last modification date of an entry
            // let's consider it was modified on UNIX_EPOCH (01/01/1970 00:00:00)
            e2.last_modification_date
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .cmp(&e1.last_modification_date.unwrap_or(SystemTime::UNIX_EPOCH))
        }),
    };

    if let SortingOrder::Asc = query_params.order.unwrap_or(config.default_sorting_order) {
        entries.reverse()
    }

    // List directories first
    if config.dirs_first {
        entries.sort_by_key(|e| !e.is_dir());
    }

    // 处理归档下载
    if let Some(archive_method) = query_params.download {
        if !archive_method.is_enabled(
            config.tar_enabled,
            config.tar_gz_enabled,
            config.zip_enabled,
        ) {
            return (StatusCode::FORBIDDEN, "Archive creation is disabled.").into_response();
        }

        log::info!(
            "Creating an archive ({extension}) of {path}...",
            extension = archive_method.extension(),
            path = &dir.path.display().to_string()
        );

        let file_name = format!(
            "{}.{}",
            dir.path.file_name().unwrap().to_str().unwrap(),
            archive_method.extension()
        );

        // 创建流式响应
        let (tx, rx) = mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(10);
        let pipe = crate::pipe::Pipe::new(tx);

        // 在后台线程中创建归档
        let dir_path = dir.path.clone();
        let skip_symlinks = config.no_symlinks;
        tokio::spawn(async move {
            if let Err(err) = archive_method.create_archive(dir_path, skip_symlinks, pipe) {
                log::error!("Error during archive creation: {:?}", err);
            }
        });

        let body = Body::from_stream(rx);

        let mut response = Response::new(body);
        response.headers_mut().insert(
            "content-type",
            HeaderValue::from_str(&archive_method.content_type())
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        );
        response.headers_mut().insert(
            "content-transfer-encoding",
            HeaderValue::from_static("binary"),
        );
        response.headers_mut().insert(
            "content-disposition",
            HeaderValue::from_str(&format!("attachment; filename={:?}", file_name)).unwrap(),
        );

        return response;
    } else {
        // 渲染 HTML 页面
        let html_content = render::page(
            entries,
            readme,
            &uri,
            is_root,
            query_params,
            &breadcrumbs,
            &encoded_dir,
            &config,
            current_user.as_ref(),
        )
        .into_string();

        let mut response = Response::new(Body::from(html_content));
        response.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("text/html; charset=utf-8"),
        );

        response
    }
}

fn markdown_to_html(content: &str, options: &comrak::ComrakOptions) -> String {
    comrak::markdown_to_html(content, options)
}
