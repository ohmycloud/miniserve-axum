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
use axum::extract::{Multipart, Query, State, multipart::Field};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect};
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

use crate::DuplicateFile;
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
                if let Ok(metadata) = entry.metadata().await
                    && metadata.is_file()
                {
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
    mut file_path: PathBuf,
    on_duplicate_files: DuplicateFile,
    file_checksum: Option<&FileHash>,
    temporary_upload_directory: Option<&PathBuf>,
    expected_size: Option<u64>,
    #[cfg(unix)] chmod: u16,
) -> Result<u64, RuntimeError> {
    if file_path.exists() {
        match on_duplicate_files {
            DuplicateFile::Error => return Err(RuntimeError::DuplicateFileError),
            DuplicateFile::Overwrite => (),
            DuplicateFile::Rename => {
                let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
                let ext = file_path.extension().map(|s| s.to_string_lossy());
                for i in 1.. {
                    let name = match &ext {
                        Some(ext) => format!("{stem}-{i}.{ext}"),
                        None => format!("{stem}-{i}"),
                    };
                    let candidate = file_path.with_file_name(name);
                    if !candidate.exists() {
                        file_path = candidate;
                        break;
                    }
                }
            }
        }
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
    while let Some(chunk) = field.next().await {
        let bytes = match chunk {
            Ok(bytes) => bytes,
            Err(error) => {
                save_upload_file_error = Some(RuntimeError::MultipartError(error.to_string()));
                break;
            }
        };
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
    if let Some(expected) = expected_size
        && written_len != expected
    {
        warn!(
            "Expected file size {} did not match received size {}. Treating as aborted upload.",
            expected, written_len
        );
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(RuntimeError::UploadHashMismatchError);
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file_path, std::fs::Permissions::from_mode(chmod.into()))
            .await
            .map_err(|e| {
                RuntimeError::IoError(format!("Failed to chmod {chmod:o} {file_path:?}"), e)
            })?;
    }

    Ok(written_len)
}

struct HandleMultipartOpts<'a> {
    on_duplicate_files: DuplicateFile,
    allow_mkdir: bool,
    allow_hidden_paths: bool,
    allow_symlinks: bool,
    file_hash: Option<&'a FileHash>,
    upload_directory: Option<&'a PathBuf>,
    expected_size: Option<u64>,
    #[cfg(unix)]
    chmod: u16,
}

/// Handles a single field in a multipart form
async fn handle_multipart(
    mut field: Field<'_>,
    path: PathBuf,
    opts: HandleMultipartOpts<'_>,
) -> Result<u64, RuntimeError> {
    let HandleMultipartOpts {
        on_duplicate_files,
        allow_mkdir,
        allow_hidden_paths,
        allow_symlinks,
        file_hash,
        upload_directory,
        expected_size,
        #[cfg(unix)]
        chmod,
    } = opts;
    let field_name = field.name().expect("No name field found").to_string();

    match tokio::fs::metadata(&path).await {
        Err(_) => Err(RuntimeError::InsufficientPermissionsError(
            path.display().to_string(),
        )),
        Ok(metadata) if !metadata.is_dir() => Err(RuntimeError::InvalidPathError(format!(
            "cannot upload file to {}, since it's not a directory",
            path.display()
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

    // Multipart quoted-string values escape backslashes; Actix decoded these before
    // handing filenames to the upload handler.
    let filename = filename.replace("\\\\", "\\");
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
        on_duplicate_files,
        file_hash,
        upload_directory,
        expected_size,
        #[cfg(unix)]
        chmod,
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
pub async fn upload_file_handler(
    State(conf): State<Arc<MiniserveConfig>>,
    Query(query): Query<FileOpQueryParameters>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> axum::response::Response {
    if !conf.file_upload || conf.path.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }
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
                on_duplicate_files: conf.on_duplicate_files,
                allow_mkdir: conf.mkdir_enabled,
                allow_hidden_paths: conf.show_hidden,
                allow_symlinks: !conf.no_symlinks,
                file_hash: hash_ref,
                upload_directory,
                expected_size,
                #[cfg(unix)]
                chmod: conf.upload_chmod,
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

pub async fn rm_file_handler(
    State(conf): State<Arc<MiniserveConfig>>,
    Query(query): Query<FileOpQueryParameters>,
    headers: HeaderMap,
) -> axum::response::Response {
    if !conf.rm_enabled || conf.path.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(path) = sanitize_path(&query.path, conf.show_hidden) else {
        return RuntimeError::InvalidPathError("Invalid value for 'path' parameter".into())
            .into_response();
    };
    if path.as_os_str().is_empty() {
        return RuntimeError::RmForbiddenError.into_response();
    }
    if !conf.allowed_rm_dir.is_empty()
        && !conf
            .allowed_rm_dir
            .iter()
            .any(|allowed| path.starts_with(allowed))
    {
        return RuntimeError::RmForbiddenError.into_response();
    }
    let Ok(root) = conf.path.canonicalize() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let target = root.join(&path);
    let Some(parent) = target.parent() else {
        return RuntimeError::RmForbiddenError.into_response();
    };
    let Ok(canonical_parent) = parent.canonicalize() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if conf.no_symlinks
        && (!canonical_parent.starts_with(&root) || contains_symlink(&target).unwrap_or(true))
    {
        return RuntimeError::RmForbiddenError.into_response();
    }
    let target = canonical_parent.join(target.file_name().unwrap_or_default());
    let Ok(metadata) = fs::symlink_metadata(&target).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let result = if metadata.is_dir() {
        fs::remove_dir_all(&target).await
    } else {
        fs::remove_file(&target).await
    };
    if let Err(error) = result {
        return RuntimeError::IoError(format!("Failed to remove {path:?}"), error).into_response();
    }
    Redirect::to(
        headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("/"),
    )
    .into_response()
}
