use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::IntoResponse,
};
use bytesize::ByteSize;
use log::info;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{MiniserveConfig, STYLESHEET, file_utils, recursive_dir_size};

#[derive(Debug, Deserialize, Serialize)]
pub enum ApiCommand {
    /// Request the size of a particular directory
    DirSize(String),
}

pub async fn favicon() -> impl IntoResponse {
    let logo = include_str!("../../data/logo.svg");
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/css"));

    (headers, logo)
}

pub async fn css(State(inside_config): State<Arc<MiniserveConfig>>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/css"));
    let stylesheet = [
        STYLESHEET,
        inside_config.default_color_scheme.css(),
        inside_config.default_color_scheme_dark.css_dark().as_str(),
    ]
    .join("\n");

    (headers, stylesheet)
}

pub async fn api(
    State(config): State<Arc<MiniserveConfig>>,
    Json(command): Json<ApiCommand>,
) -> impl IntoResponse {
    match command {
        ApiCommand::DirSize(path) => {
            if config.directory_size {
                // The dir argument might be percent-encoded so let's decode it just in case.
                let decoded_path = percent_decode_str(&path).decode_utf8().unwrap();

                // Convert the relative dir to an absolute path on the system.
                let sanitized_path = file_utils::sanitize_path(&*decoded_path, true)
                    .expect("Expected a path to directory");

                let full_path = config
                    .path
                    .canonicalize()
                    .expect("Couldn't canonicalize path")
                    .join(sanitized_path);
                info!("Requested directory listing for {full_path:?}");

                let dir_size = recursive_dir_size(&full_path).await.unwrap();
                if config.show_exact_bytes {
                    format!("{dir_size} B")
                } else {
                    let dir_size = ByteSize::b(dir_size);
                    dir_size.to_string()
                }
            } else {
                "-".to_string()
            }
        }
    }
}
