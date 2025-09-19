use crate::MiniserveConfig;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
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
