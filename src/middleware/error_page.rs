use std::{str::FromStr, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, header},
    middleware::Next,
    response::Response,
};

use crate::{MiniserveConfig, render_error};

pub async fn error_page_middleware(
    State(config): State<Arc<MiniserveConfig>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let return_address = request
        .headers()
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/")
        .to_owned();
    let response = next.run(request).await;
    let is_text = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| mime::Mime::from_str(v).ok())
        .is_none_or(|v| v.essence_str() == mime::TEXT_PLAIN.as_ref());
    if !(response.status().is_client_error() || response.status().is_server_error())
        || path.ends_with("/upload")
        || !is_text
    {
        return response;
    }
    let status = response.status();
    let (mut parts, body) = response.into_parts();
    let bytes = to_bytes(body, 1024 * 1024).await.unwrap_or_default();
    let message = if bytes.is_empty() {
        status.to_string()
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Response::from_parts(
        parts,
        Body::from(render_error(&message, status, &config, &return_address).into_string()),
    )
}
