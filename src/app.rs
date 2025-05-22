use axum::{
    extract::{Request, State},
    http::{StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dav_server::DavHandler;

use crate::MiniserveConfig;

// Middleware to handle pretty URLs, hidden files, and symlink filtering
async fn file_middleware(
    State(conf): State<MiniserveConfig>,
    request: Request,
    next: Next,
) -> Response {
    let uri = request.uri();
    let path = uri.path();

    // Handle symlink filtering
    if conf.no_symlinks {
        let file_path = conf.path.join(&path[1..]);
        if file_path.is_symlink() {
            return StatusCode::FORBIDDEN.into_response();
        }
    }

    // Handle pretty URLs
    if conf.pretty_urls && should_try_html_extension(path) {
        let mut path_base = path[1..].to_string();
        if path_base.ends_with('/') {
            path_base.pop();
        }
        if !path_base.ends_with(".html") {
            path_base = format!("{}.html", path_base);
        }
        let html_file_path = conf.path.join(&path_base);
        if html_file_path.exists() && html_file_path.is_file() {
            // Modify the request to point to the .html file
            let new_uri = format!("/{}", path_base);
            if let Ok(new_uri) = new_uri.parse::<Uri>() {
                let (mut parts, body) = request.into_parts();
                parts.uri = new_uri;
                let new_request = Request::from_parts(parts, body);
                return next.run(new_request).await;
            }
        }
    }

    next.run(request).await
}

/// WebDAV request handler
async fn dav_handler(State(dav_server): State<DavHandler>, request: Request) -> impl IntoResponse {
    // Forward the request to the WebDAV handler
    dav_server.handle(request).await
}

/// Helper function to determine if we should try adding .html extension
fn should_try_html_extension(path: &str) -> bool {
    !path.ends_with('/') && !path.contains('.') && path != "/" && !path.is_empty()
}
