use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::Body,
    extract::{OriginalUri, Query, Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use dav_server::{DavHandler, DavMethodSet};
use percent_encoding::percent_decode_str;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::{
    CurrentUser, ListingQueryParameters, MiniserveConfig, RestrictedFs, contains_symlink,
    directory_listing, sanitize_path,
};

pub async fn serve_handler(
    State(config): State<Arc<MiniserveConfig>>,
    OriginalUri(original_uri): OriginalUri,
    Query(query): Query<ListingQueryParameters>,
    request: Request,
) -> Response {
    if request.method().as_str() == "PROPFIND" || request.method() == Method::OPTIONS {
        if !config.webdav_enabled {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        let dav = DavHandler::builder()
            .filesystem(RestrictedFs::new(
                &config.path,
                config.show_hidden,
                config.no_symlinks,
            ))
            .methods(DavMethodSet::WEBDAV_RO)
            .hide_symlinks(false)
            .strip_prefix(config.route_prefix.clone())
            .build_handler();
        return dav.handle(request).await.into_response();
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let route = original_uri
        .path()
        .strip_prefix(&config.route_prefix)
        .unwrap_or(original_uri.path());
    let Ok(decoded) = percent_decode_str(route).decode_utf8() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let relative = Path::new(decoded.trim_start_matches('/'));
    let Some(normalized) = sanitize_path(relative, config.show_hidden) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let root = match config.path.canonicalize() {
        Ok(path) => path,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let path = if config.path.is_file() {
        if !normalized.as_os_str().is_empty() {
            return StatusCode::NOT_FOUND.into_response();
        }
        root.clone()
    } else {
        root.join(normalized)
    };
    let mut selected = path.clone();
    if config.no_symlinks && contains_symlink(&selected).unwrap_or(true) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !selected.exists() && config.pretty_urls {
        let html = format!("{}.html", selected.to_string_lossy().trim_end_matches('/'));
        if Path::new(&html).is_file() {
            selected = PathBuf::from(html);
        }
    }
    if !selected.exists()
        && config.spa
        && let Some(index) = &config.index
    {
        selected = root.join(index);
    }
    if !selected.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if config.no_symlinks {
        if contains_symlink(&selected).unwrap_or(true) {
            return StatusCode::NOT_FOUND.into_response();
        }
        if !selected.canonicalize().is_ok_and(|p| p.starts_with(&root)) {
            return StatusCode::NOT_FOUND.into_response();
        }
    }

    if selected.is_dir() {
        if !original_uri.path().ends_with('/') {
            let suffix = original_uri
                .path_and_query()
                .and_then(|p| p.query())
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            return Redirect::permanent(&format!("{}/{}", original_uri.path(), suffix))
                .into_response();
        }
        if let Some(index) = &config.index {
            let index_path = selected.join(index);
            if index_path.is_file()
                && (!config.no_symlinks || !contains_symlink(&index_path).unwrap_or(true))
            {
                return serve_file(index_path, request).await;
            }
        }
        let user = request.extensions().get::<CurrentUser>().cloned();
        let headers = request.headers().clone();
        let response =
            directory_listing(selected, original_uri, headers, query, State(config), user).await;
        if request.method() == Method::HEAD {
            let (parts, _) = response.into_parts();
            Response::from_parts(parts, Body::empty())
        } else {
            response
        }
    } else {
        serve_file(selected, request).await
    }
}

async fn serve_file(path: PathBuf, request: Request) -> Response {
    match ServeFile::new(path).oneshot(request).await {
        Ok(response) => response.map(Body::new),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
