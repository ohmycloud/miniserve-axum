use crate::{MiniserveConfig, BasicAuthParams, CurrentUser, match_auth};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{Response, IntoResponse},
};
use base64::Engine as _;
use std::sync::Arc;

pub mod error_page;

pub async fn configure_header(
    State(state): State<Arc<MiniserveConfig>>,
    req: Request,
    next: Next,
) -> Response {
    let mut headers = HeaderMap::new();

    for (header_name, header_value) in state.header.iter().flatten() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(header_name.as_ref()),
            HeaderValue::from_bytes(header_value.as_bytes()),
        ) {
            headers.insert(name, value);
        }
    }
    let mut res = next.run(req).await;
    for (header_name, header_value) in headers {
        res.headers_mut().insert(header_name.unwrap(), header_value);
    }
    res
}

/// Basic Auth middleware: if `auth` is configured, require valid `Authorization: Basic ...`.
pub async fn basic_auth_guard(
    State(state): State<Arc<MiniserveConfig>>,
    mut req: Request,
    next: Next,
) -> Response {
    fn unauthorized_response() -> Response {
        let mut res = StatusCode::UNAUTHORIZED.into_response();
        res.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"miniserve\""),
        );
        res
    }
    // If no auth configured, allow all requests.
    if state.auth.is_empty() {
        return next.run(req).await;
    }

    // Allow healthcheck route without auth to avoid noisy probes failing auth.
    let path = req.uri().path();
    if path == state.healthcheck_route {
        return next.run(req).await;
    }

    // Parse `Authorization: Basic base64(user:pass)`
    let Some(auth_header) = req.headers().get(AUTHORIZATION) else {
        return unauthorized_response();
    };
    let Ok(auth_str) = auth_header.to_str() else {
        return unauthorized_response();
    };
    let prefix = "Basic ";
    if !auth_str.starts_with(prefix) {
        return unauthorized_response();
    }
    let b64 = &auth_str[prefix.len()..];
    let decoded = match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => return unauthorized_response(),
    };
    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return unauthorized_response(),
    };
    let mut split = decoded_str.splitn(2, ':');
    let username = match split.next() { Some(u) => u, None => "" };
    let password = match split.next() { Some(p) => p, None => "" };

    let creds = BasicAuthParams { username: username.to_string(), password: password.to_string() };
    if !match_auth(&creds, &state.auth) {
        return unauthorized_response();
    }

    // Attach current user to request extensions for downstream handlers (optional use)
    req.extensions_mut().insert(CurrentUser { name: username.to_string() });

    next.run(req).await
}
