use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::IntoResponse,
};

pub async fn favicon() -> impl IntoResponse {
    let logo = include_str!("../../data/logo.svg");
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/css"));

    (headers, logo)
}

pub async fn css(State(stylesheet): State<String>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/css"));

    (headers, stylesheet)
}
