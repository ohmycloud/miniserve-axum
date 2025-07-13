use std::sync::Arc;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::IntoResponse,
};

use crate::{MiniserveConfig, STYLESHEET};

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
