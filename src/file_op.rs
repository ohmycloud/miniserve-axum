//! Handlers for file upload and removal

#[cfg(target_family = "unix")]
use std::collections::HashSet;

use std::io::ErrorKind;

#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

use std::path::{Component, Path, PathBuf};

#[cfg(target_family = "unix")]
use std::sync::Arc;

use async_walkdir::WalkDir;
use axum::body::Body;
use axum::extract::{Multipart, Query, State, multipart::Field};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Redirect};
use bytesize::ByteSize;
use futures::{StreamExt, TryStreamExt};
use log::{error, info, warn};
use serde::Deserialize;
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256, Sha512};
use tempfile::NamedTempFile;
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[cfg(target_family = "unix")]
use tokio::sync::RwLock;

use crate::{ArchiveMethod, Breadcrumb, Entry, EntryType, ListingQueryParameters, page};
use crate::{
    config::MiniserveConfig, errors::RuntimeError, file_utils::contains_symlink,
    file_utils::sanitize_path,
};

enum FileHash {
    SHA256(String),
    SHA512(String),
}

impl FileHash {
    pub fn get_hasher(&self) -> Box<dyn DynDigest + Send> {
        match self {
            Self::SHA256(_) => Box::new(Sha256::new()),
            Self::SHA512(_) => Box::new(Sha512::new()),
        }
    }

    pub fn get_hash(&self) -> &str {
        match self {
            Self::SHA256(string) => string,
            Self::SHA512(string) => string,
        }
    }
}

#[derive(serde::Deserialize)]
pub struct DownloadQuery {
    download: Option<ArchiveMethod>,
}

/// Get the recursively calculated dir size for a given dir
///
/// Counts hardlinked files only once if the OS supports hardlinks.
///
/// Expects `dir` to be sanitized. This function doesn't do any sanitization itself.
pub async fn recursive_dir_size(dir: &Path) -> Result<u64, RuntimeError> {
    #[cfg(target_family = "unix")]
    let seen_inodes = Arc::new(RwLock::new(HashSet::new()));

    let mut entries = WalkDir::new(dir);

    let mut total_size = 0;
    loop {
        match entries.next().await {
            Some(Ok(entry)) => {
                if let Ok(metadata) = entry.metadata().await {
                    if metadata.is_file() {
                        // On Unix, we want to filter inodes that we've already seen so we get a
                        // more accurate count of real size used on disk.
                        #[cfg(target_family = "unix")]
                        {
                            let (device_id, inode) = (metadata.dev(), metadata.ino());

                            // Check if this file has been seen before based on its device ID and
                            // inode number
                            if seen_inodes.read().await.contains(&(device_id, inode)) {
                                continue;
                            } else {
                                seen_inodes.write().await.insert((device_id, inode));
                            }
                        }
                        total_size += metadata.len();
                    }
                }
            }
            Some(Err(e)) => {
                if let Some(io_err) = e.into_io() {
                    match io_err.kind() {
                        ErrorKind::PermissionDenied => warn!(
                            "Error trying to read file when calculating dir size: {io_err}, ignoring"
                        ),
                        _ => return Err(RuntimeError::InvalidPathError(io_err.to_string())),
                    }
                }
            }
            None => break,
        }
    }
    Ok(total_size)
}

/// Saves file data from a multipart form field (`field`) to `file_path`. Optionally overwriting
/// existing file and comparing the uploaded file checksum to the user provided `file_hash`.
///
/// Returns total bytes written to file.
async fn save_file(
    field: &mut Field<'_>,
    file_path: PathBuf,
    overwrite_files: bool,
    file_checksum: Option<&FileHash>,
    temporary_upload_directory: Option<&PathBuf>,
    expected_size: Option<u64>,
) -> Result<u64, RuntimeError> {
    if !overwrite_files && file_path.exists() {
        return Err(RuntimeError::DuplicateFileError);
    }

    let temp_upload_directory = temporary_upload_directory.cloned();
    // Tempfile doesn't support async operations, so we'll do it on a background thread.
    let temp_upload_directory_task = tokio::task::spawn_blocking(move || {
        // If the user provided a temporary directory path, then use it.
        if let Some(temp_directory) = temp_upload_directory {
            NamedTempFile::new_in(temp_directory)
        } else {
            NamedTempFile::new()
        }
    });

    // Validate that the temporary task completed successfully.
    let named_temp_file_task = match temp_upload_directory_task.await {
        Ok(named_temp_file) => Ok(named_temp_file),
        Err(err) => Err(RuntimeError::MultipartError(format!(
            "Failed to complete spawned task to create named temp file. {err}",
        ))),
    }?;

    // Validate the the temporary file was created successfully.
    let named_temp_file = match named_temp_file_task {
        Err(err) if err.kind() == ErrorKind::PermissionDenied => Err(
            RuntimeError::InsufficientPermissionsError(file_path.display().to_string()),
        ),
        Err(err) => Err(RuntimeError::IoError(
            format!("Failed to create temporary file {}", file_path.display()),
            err,
        )),
        Ok(file) => Ok(file),
    }?;

    // Convert the temporary file into a non-temporary file. This allows us
    // to control the lifecycle of the file. This is useful for us because
    // we need to convert the temporary file into an async enabled file and
    // on successful upload, we want to move it to the target directory.
    let (file, temp_path) = named_temp_file
        .keep()
        .map_err(|err| RuntimeError::IoError("Failed to keep temporary file".into(), err.error))?;
    let mut temp_file = tokio::fs::File::from_std(file);

    let mut written_len = 0;
    // If the client provided a checksum header, prepare a hasher and update it as we stream bytes.
    let mut stream_hasher = file_checksum.as_ref().map(|h| h.get_hasher());
    let mut save_upload_file_error: Option<RuntimeError> = None;

    // This while loop take a stream (in this case `field`) and awaits
    // new chunks from the websocket connection. The while loop reads
    // the file from the HTTP connection and writes it to disk or until
    // the stream from the multipart request is aborted.
    while let Some(Ok(bytes)) = field.next().await {
        // Update hash with the streamed bytes, if requested
        if let Some(hasher) = stream_hasher.as_mut() {
            hasher.update(&bytes);
        }
        // Write the bytes from the stream into our temporary file.
        if let Err(e) = temp_file.write_all(&bytes).await {
            // Failed to write to file. Drop it and return the error
            save_upload_file_error =
                Some(RuntimeError::IoError("Failed to write to file".into(), e));
            break;
        }
        // record the bytes written to the file.
        written_len += bytes.len() as u64;
    }

    if save_upload_file_error.is_none() {
        // Flush the changes to disk so that we are sure they are there.
        if let Err(e) = temp_file.flush().await {
            save_upload_file_error = Some(RuntimeError::IoError(
                "Failed to flush all the file writes to disk".into(),
                e,
            ));
        }
    }

    // Drop the file expcitly here because IF there is an error when writing to the
    // temp file, we won't be able to remove as per the comment in `tokio::fs::remove_file`
    // > Note that there is no guarantee that the file is immediately deleted
    // > (e.g. depending on platform, other open file descriptors may prevent immediate removal).
    drop(temp_file);

    // If there was an error during uploading.
    if let Some(e) = save_upload_file_error {
        // If there was an error when writing the file to disk, remove it and return
        // the error that was encountered.
        let _ = tokio::fs::remove_file(temp_path).await;
        return Err(e);
    }

    // Validate size if the client sent X-File-Size
    if let Some(expected) = expected_size {
        if written_len != expected {
            warn!(
                "Expected file size {} did not match received size {}. Treating as aborted upload.",
                expected, written_len
            );
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(RuntimeError::UploadHashMismatchError);
        }
    }

    // After fully writing, if a checksum was provided by client, compare against streamed hash.
    if let (Some(hasher), Some(expected_hash)) =
        (stream_hasher, file_checksum.as_ref().map(|f| f.get_hash()))
    {
        let expected_hash = expected_hash.to_ascii_lowercase();
        let actual_hash = hex::encode(hasher.finalize());
        if actual_hash != expected_hash {
            warn!(
                "The expected file hash {expected_hash} did not match the calculated hash of {actual_hash}. This can be caused if a file upload was aborted."
            );
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(RuntimeError::UploadHashMismatchError);
        }
    }

    info!("File upload successful to {temp_path:?}. Moving to {file_path:?}",);
    if let Err(err) = tokio::fs::rename(&temp_path, &file_path).await {
        match err.kind() {
            ErrorKind::CrossesDevices => {
                warn!(
                    "File writen to {temp_path:?} must be copied to {file_path:?} because it's on a different filesystem"
                );
                let copy_result = tokio::fs::copy(&temp_path, &file_path).await;
                if let Err(e) = tokio::fs::remove_file(&temp_path).await {
                    error!("Failed to clean up temp file at {temp_path:?} with error {e:?}");
                }
                copy_result.map_err(|e| {
                    RuntimeError::IoError(
                        format!("Failed to copy file from {temp_path:?} to {file_path:?}"),
                        e,
                    )
                })?;
            }
            _ => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(RuntimeError::IoError(
                    format!("Failed to move temporary file {temp_path:?} to {file_path:?}",),
                    err,
                ));
            }
        }
    }

    Ok(written_len)
}

struct HandleMultipartOpts<'a> {
    overwrite_files: bool,
    allow_mkdir: bool,
    allow_hidden_paths: bool,
    allow_symlinks: bool,
    file_hash: Option<&'a FileHash>,
    upload_directory: Option<&'a PathBuf>,
    expected_size: Option<u64>,
}

/// Handles a single field in a multipart form
async fn handle_multipart(
    mut field: Field<'_>,
    path: PathBuf,
    opts: HandleMultipartOpts<'_>,
) -> Result<u64, RuntimeError> {
    let HandleMultipartOpts {
        overwrite_files,
        allow_mkdir,
        allow_hidden_paths,
        allow_symlinks,
        file_hash,
        upload_directory,
        expected_size,
    } = opts;
    let field_name = field.name().expect("No name field found").to_string();

    match tokio::fs::metadata(&path).await {
        Err(_) => Err(RuntimeError::InsufficientPermissionsError(
            path.display().to_string(),
        )),
        Ok(metadata) if !metadata.is_dir() => Err(RuntimeError::InvalidPathError(format!(
            "cannot upload file to {}, since it's not a directory",
            &path.display()
        ))),
        Ok(_) => Ok(()),
    }?;

    if field_name == "mkdir" {
        if !allow_mkdir {
            return Err(RuntimeError::InsufficientPermissionsError(
                path.display().to_string(),
            ));
        }

        let mut user_given_path = PathBuf::new();
        let mut absolute_path = path.clone();

        // Get the path the user gave
        let mkdir_path_bytes = field.try_next().await;
        match mkdir_path_bytes {
            Ok(Some(mkdir_path_bytes)) => {
                let mkdir_path = std::str::from_utf8(&mkdir_path_bytes).map_err(|e| {
                    RuntimeError::ParseError(
                        "Failed to parse 'mkdir' path".to_string(),
                        e.to_string(),
                    )
                })?;
                let mkdir_path = mkdir_path.replace('\\', "/");
                absolute_path.push(&mkdir_path);
                user_given_path.push(&mkdir_path);
            }
            _ => {
                return Err(RuntimeError::ParseError(
                    "Failed to parse 'mkdir' path".to_string(),
                    "".to_string(),
                ));
            }
        };

        // Disallow using `..` (parent) in mkdir path
        if user_given_path
            .components()
            .any(|c| c == Component::ParentDir)
        {
            return Err(RuntimeError::InvalidPathError(
                "Cannot use '..' in mkdir path".to_string(),
            ));
        }
        // Hidden paths check
        sanitize_path(&user_given_path, allow_hidden_paths).ok_or_else(|| {
            RuntimeError::InvalidPathError("Cannot use hidden paths in mkdir path".to_string())
        })?;

        // Ensure there are no illegal symlinks
        if !allow_symlinks {
            match contains_symlink(&absolute_path) {
                Err(err) => Err(RuntimeError::InsufficientPermissionsError(err.to_string()))?,
                Ok(true) => Err(RuntimeError::InsufficientPermissionsError(format!(
                    "{user_given_path:?} traverses through a symlink"
                )))?,
                Ok(false) => (),
            }
        }

        return match tokio::fs::create_dir_all(&absolute_path).await {
            Err(err) if err.kind() == ErrorKind::PermissionDenied => Err(
                RuntimeError::InsufficientPermissionsError(path.display().to_string()),
            ),
            Err(err) => Err(RuntimeError::IoError(
                format!("Failed to create {}", user_given_path.display()),
                err,
            )),
            Ok(_) => Ok(0),
        };
    }

    let filename = field.file_name().ok_or_else(|| {
        RuntimeError::ParseError(
            "HTTP header".to_string(),
            "Failed to retrieve the name of the file to upload".to_string(),
        )
    })?;

    let filename_path = sanitize_path(Path::new(&filename), allow_hidden_paths)
        .ok_or_else(|| RuntimeError::InvalidPathError("Invalid file name to upload".to_string()))?;

    // Ensure there are no illegal symlinks in the file upload path
    if !allow_symlinks {
        match contains_symlink(&path) {
            Err(err) => Err(RuntimeError::InsufficientPermissionsError(err.to_string()))?,
            Ok(true) => Err(RuntimeError::InsufficientPermissionsError(format!(
                "{path:?} traverses through a symlink"
            )))?,
            Ok(false) => (),
        }
    }

    save_file(
        &mut field,
        path.join(filename_path),
        overwrite_files,
        file_hash,
        upload_directory,
        expected_size,
    )
    .await
}

/// Query parameters used by upload and rm APIs
#[derive(Deserialize, Default)]
pub struct FileOpQueryParameters {
    path: PathBuf,
}

/// Handle incoming request to upload a file or create a directory.
/// Target file path is expected as path parameter in URI and is interpreted as relative from
/// server root directory. Any path which will go outside of this directory is considered
/// invalid.
/// This method returns future.
pub async fn upload_file(
    State(conf): State<Arc<MiniserveConfig>>,
    Query(query): Query<FileOpQueryParameters>,
    headers: axum::http::HeaderMap,
    mut multipart: Multipart,
) -> Result<axum::response::Response, RuntimeError> {
    let upload_path = sanitize_path(&query.path, conf.show_hidden).ok_or_else(|| {
        RuntimeError::InvalidPathError("Invalid value for 'path' parameter".to_string())
    })?;
    let app_root_dir = conf.path.canonicalize().map_err(|e| {
        RuntimeError::IoError("Failed to resolve path served by miniserve".to_string(), e)
    })?;

    // Disallow paths outside of allowed directories
    let upload_allowed = conf.allowed_upload_dir.is_empty()
        || conf
            .allowed_upload_dir
            .iter()
            .any(|s| upload_path.starts_with(s));

    if !upload_allowed {
        return Err(RuntimeError::UploadForbiddenError);
    }

    // Disallow the target path to go outside of the served directory
    // The target directory shouldn't be canonicalized when it gets passed to
    // handle_multipart so that it can check for symlinks if needed
    let non_canonicalized_target_dir = app_root_dir.join(upload_path);
    match non_canonicalized_target_dir.canonicalize() {
        Ok(path) if !conf.no_symlinks => Ok(path),
        Ok(path) if path.starts_with(&app_root_dir) => Ok(path),
        _ => Err(RuntimeError::InvalidHttpRequestError(
            "Invalid value for 'path' parameter".to_string(),
        )),
    }?;

    let upload_directory = conf.temp_upload_directory.as_ref();
    // Optional expected size header (provided by client)
    let expected_size = headers
        .get("X-File-Size")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let file_hash = if let (Some(hash), Some(hash_function)) = (
        headers.get("X-File-Hash").and_then(|h| h.to_str().ok()),
        headers
            .get("X-File-Hash-Function")
            .and_then(|h| h.to_str().ok()),
    ) {
        match hash_function.to_ascii_uppercase().as_str() {
            "SHA256" => Some(FileHash::SHA256(hash.to_string())),
            "SHA512" => Some(FileHash::SHA512(hash.to_string())),
            sha => {
                return Err(RuntimeError::InvalidHttpRequestError(format!(
                    "Invalid header value found for 'X-File-Hash-Function'. Supported values are SHA256 or SHA512. Found {sha}.",
                )));
            }
        }
    } else {
        None
    };

    let hash_ref = file_hash.as_ref();
    // Process multipart form
    let mut sizes = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| RuntimeError::MultipartError(e.to_string()))?
    {
        let size = handle_multipart(
            field,
            non_canonicalized_target_dir.clone(),
            HandleMultipartOpts {
                overwrite_files: conf.overwrite_files,
                allow_mkdir: conf.mkdir_enabled,
                allow_hidden_paths: conf.show_hidden,
                allow_symlinks: !conf.no_symlinks,
                file_hash: hash_ref,
                upload_directory,
                expected_size,
            },
        )
        .await?;

        sizes.push(size);
    }

    // Get the referer for redirect
    let return_path = headers
        .get(header::REFERER)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("/");

    // Redirect to the referring page
    Ok(Redirect::to(return_path).into_response())
}

pub async fn upload_file_handler(
    State(conf): State<Arc<MiniserveConfig>>,
    Query(query): Query<FileOpQueryParameters>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> axum::response::Response {
    log::info!("Upload request received!");

    // Sanitize and validate target path
    let upload_path = match sanitize_path(&query.path, conf.show_hidden) {
        Some(p) => p,
        None => {
            return RuntimeError::InvalidPathError(
                "Invalid value for 'path' parameter".to_string(),
            )
            .into_response();
        }
    };

    let app_root_dir = match conf.path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return RuntimeError::IoError(
                "Failed to resolve path served by miniserve".to_string(),
                e,
            )
            .into_response();
        }
    };

    // Allow only configured upload directories
    let upload_allowed = conf.allowed_upload_dir.is_empty()
        || conf
            .allowed_upload_dir
            .iter()
            .any(|s| upload_path.starts_with(s));
    if !upload_allowed {
        return RuntimeError::UploadForbiddenError.into_response();
    }

    // Disallow the target path to go outside of the served directory
    let non_canonicalized_target_dir = app_root_dir.join(&upload_path);
    let within_root = match non_canonicalized_target_dir.canonicalize() {
        Ok(path) if !conf.no_symlinks => path,
        Ok(path) if path.starts_with(&app_root_dir) => path,
        _ => {
            return RuntimeError::InvalidHttpRequestError(
                "Invalid value for 'path' parameter".to_string(),
            )
            .into_response();
        }
    };
    let _ = within_root; // only used for validation above

    // Optional file hash headers
    let file_hash = if let (Some(hash), Some(hash_function)) = (
        headers.get("X-File-Hash").and_then(|h| h.to_str().ok()),
        headers
            .get("X-File-Hash-Function")
            .and_then(|h| h.to_str().ok()),
    ) {
        match hash_function.to_ascii_uppercase().as_str() {
            "SHA256" => Some(FileHash::SHA256(hash.to_string())),
            "SHA512" => Some(FileHash::SHA512(hash.to_string())),
            sha => {
                return RuntimeError::InvalidHttpRequestError(format!(
                    "Invalid header value found for 'X-File-Hash-Function'. Supported values are SHA256 or SHA512. Found {sha}.",
                ))
                .into_response();
            }
        }
    } else {
        None
    };
    let hash_ref = file_hash.as_ref();

    let upload_directory = conf.temp_upload_directory.as_ref();
    // Optional expected size header (provided by client)
    let expected_size = headers
        .get("X-File-Size")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    // Process multipart fields (mkdir or file uploads)
    while let Some(field) = match multipart.next_field().await {
        Ok(f) => f,
        Err(e) => return RuntimeError::MultipartError(e.to_string()).into_response(),
    } {
        if let Err(e) = handle_multipart(
            field,
            non_canonicalized_target_dir.clone(),
            HandleMultipartOpts {
                overwrite_files: conf.overwrite_files,
                allow_mkdir: conf.mkdir_enabled,
                allow_hidden_paths: conf.show_hidden,
                allow_symlinks: !conf.no_symlinks,
                file_hash: hash_ref,
                upload_directory,
                expected_size,
            },
        )
        .await
        {
            return e.into_response();
        }
    }

    // Redirect back to referer
    let return_path = headers
        .get(axum::http::header::REFERER)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("/");
    log::info!("Upload completed, redirecting to: {}", return_path);
    axum::response::Redirect::to(return_path).into_response()
}

pub async fn file_and_directory_handler(
    uri: Uri,
    Query(download_query): Query<DownloadQuery>,
    State(config): State<Arc<MiniserveConfig>>,
) -> impl IntoResponse {
    let path_str = uri.path();
    let decoded_path = percent_encoding::percent_decode_str(path_str)
        .decode_utf8()
        .unwrap_or_default();

    // Remove leading slash and join with served directory
    let relative_path = decoded_path.strip_prefix('/').unwrap_or(&decoded_path);
    let full_path = config.path.join(relative_path);

    if !full_path.exists() {
        return (StatusCode::NOT_FOUND, "File not found").into_response();
    }

    if full_path.is_file() {
        // Serve file
        match fs::read(&full_path).await {
            Ok(contents) => {
                // Simple content type detection
                let content_type = if path_str.ends_with(".html") {
                    "text/html"
                } else if path_str.ends_with(".css") {
                    "text/css"
                } else if path_str.ends_with(".js") {
                    "application/javascript"
                } else if path_str.ends_with(".png") {
                    "image/png"
                } else if path_str.ends_with(".jpg") || path_str.ends_with(".jpeg") {
                    "image/jpeg"
                } else {
                    "application/octet-stream"
                };

                let headers = [(axum::http::header::CONTENT_TYPE, content_type)];
                (headers, contents).into_response()
            }
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Could not read file").into_response(),
        }
    } else if full_path.is_dir() {
        // Check if this is a download request
        if let Some(archive_method) = download_query.download {
            // Handle archive download
            if !archive_method.is_enabled(
                config.tar_enabled,
                config.tar_gz_enabled,
                config.zip_enabled,
            ) {
                return (StatusCode::FORBIDDEN, "Archive creation is disabled.").into_response();
            }

            log::info!(
                "Creating {} archive for path: {:?}",
                archive_method,
                full_path
            );
            log::info!("Full path exists: {}", full_path.exists());
            log::info!("Full path is_dir: {}", full_path.is_dir());
            log::info!("Full path file_name: {:?}", full_path.file_name());
            log::info!("Full path as string: {}", full_path.display());

            let file_name = format!(
                "{}.{}",
                full_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("archive"),
                archive_method.extension()
            );

            // Create archive synchronously in memory for debugging
            let mut buffer = Vec::new();
            match archive_method.create_archive(&full_path, config.no_symlinks, &mut buffer) {
                Ok(()) => {
                    log::info!("Archive created successfully! Size: {} bytes", buffer.len());

                    let mut response = Response::new(Body::from(buffer));
                    response.headers_mut().insert(
                        "content-type",
                        HeaderValue::from_str(&archive_method.content_type()).unwrap_or_else(
                            |_| HeaderValue::from_static("application/octet-stream"),
                        ),
                    );
                    response.headers_mut().insert(
                        "content-transfer-encoding",
                        HeaderValue::from_static("binary"),
                    );
                    response.headers_mut().insert(
                        "content-disposition",
                        HeaderValue::from_str(&format!("attachment; filename={:?}", file_name))
                            .unwrap(),
                    );

                    return response;
                }
                Err(err) => {
                    log::error!("Archive creation failed: {:?}", err);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Archive creation failed: {}", err),
                    )
                        .into_response();
                }
            }
        } else {
            // Generate directory listing
            match generate_directory_listing(&full_path, &uri, &config).await {
                Ok(html) => Html(html.into_string()).into_response(),
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not read directory",
                )
                    .into_response(),
            }
        }
    } else {
        (StatusCode::NOT_FOUND, "Not found").into_response()
    }
}

pub async fn generate_directory_listing(
    dir_path: &Path,
    uri: &Uri,
    config: &Arc<MiniserveConfig>,
) -> Result<maud::Markup, std::io::Error> {
    let mut entries = Vec::new();
    let mut dir_entries = fs::read_dir(dir_path).await?;

    while let Some(entry) = dir_entries.next_entry().await? {
        let file_name = entry.file_name().to_string_lossy().to_string();
        let metadata = entry.metadata().await.ok();

        let entry_type = if entry
            .file_type()
            .await
            .map(|ft| ft.is_dir())
            .unwrap_or(false)
        {
            EntryType::Directory
        } else {
            EntryType::File
        };

        let size = metadata
            .as_ref()
            .filter(|m| m.is_file())
            .map(|m| ByteSize::b(m.len()));

        let last_modification_date = metadata.as_ref().and_then(|m| m.modified().ok());

        let link = if uri.path().ends_with('/') {
            format!("{}{}", uri.path(), file_name)
        } else {
            format!("{}/{}", uri.path(), file_name)
        };

        entries.push(Entry {
            name: file_name,
            entry_type,
            link,
            size,
            last_modification_date,
            symlink_info: None,
        });
    }

    // Create breadcrumbs
    let path_components: Vec<&str> = uri
        .path()
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let mut breadcrumbs = vec![Breadcrumb {
        name: "Home".to_string(),
        link: "/".to_string(),
    }];

    let mut current_path = String::new();
    for component in path_components {
        current_path.push('/');
        current_path.push_str(component);
        breadcrumbs.push(Breadcrumb {
            name: component.to_string(),
            link: current_path.clone(),
        });
    }

    // Mark the last breadcrumb as current (don't make it a link)
    if let Some(last) = breadcrumbs.last_mut() {
        last.link = ".".to_string();
    }

    let is_root = uri.path() == "/" || uri.path().is_empty();
    let encoded_dir = uri.path().to_string();
    let query_params = ListingQueryParameters::default();

    // Use the proper miniserve page render function
    Ok(page(
        entries,
        None, // readme
        uri,
        is_root,
        query_params,
        &breadcrumbs,
        &encoded_dir,
        config,
        None, // current_user
    ))
}
