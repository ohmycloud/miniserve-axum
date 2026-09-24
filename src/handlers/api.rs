use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
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
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml"),
    );

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
) -> Response {
    match command {
        ApiCommand::DirSize(path) => {
            if config.directory_size {
                // The dir argument might be percent-encoded so let's decode it just in case.
                let Ok(decoded_path) = percent_decode_str(&path).decode_utf8() else {
                    return StatusCode::BAD_REQUEST.into_response();
                };

                // Convert the relative dir to an absolute path on the system.
                let Some(sanitized_path) =
                    file_utils::sanitize_path(&*decoded_path, config.show_hidden)
                else {
                    return StatusCode::BAD_REQUEST.into_response();
                };

                let Ok(root) = config.path.canonicalize() else {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                };
                let path = root.join(sanitized_path);
                if config.no_symlinks && file_utils::contains_symlink(&path).unwrap_or(true) {
                    return StatusCode::BAD_REQUEST.into_response();
                }
                let Ok(full_path) = path.canonicalize() else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                if config.no_symlinks && !full_path.starts_with(&root) {
                    return StatusCode::BAD_REQUEST.into_response();
                }
                info!("Requested directory listing for {full_path:?}");

                let Ok(dir_size) = recursive_dir_size(&full_path).await else {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                };
                if config.show_exact_bytes {
                    format!("{dir_size} B").into_response()
                } else {
                    let dir_size = ByteSize::b(dir_size);
                    dir_size.to_string().into_response()
                }
            } else {
                "-".into_response()
            }
        }
    }
}
