use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StartupError {
    /// Any kind of IO errors
    #[error("{0}\ncaused by: {1}")]
    IoError(String, std::io::Error),

    /// In case miniserve was invoked without an interactive terminal and without an explicit path
    #[error("Refusing to start as no explicit serve path was set and no interactive terminal was attached
Please set an explicit serve path like: `miniserve /my/path`")]
    NoExplicitPathAndNoTerminal,

    /// In case miniserve was invoked with --no-symlinks but the serve path is a symlink
    #[error("The -P|--no-symlinks option was provided but the serve path '{0}' is a symlink")]
    NoSymlinksOptionWithSymlinkServePath(String),

    #[error("The --enable-webdav option was provided, but the serve path '{0}' is a file")]
    WebdavWithFileServePath(String),
    #[error("{0}")]
    NetworkError(String),
}

pub fn log_error_chain(description: String) {
    for cause in description.lines() {
        log::error!("{}", cause);
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Any kind of IO errors
    #[error("{0}\ncaused by: {1}")]
    IoError(String, std::io::Error),

    /// Might occur during file upload, when processing the multipart request fails
    #[error("Failed to process multipart request\ncaused by: {0}")]
    MultipartError(String),

    /// Might occur during file upload
    #[error("File already exists, and the overwrite_files option has not been set")]
    DuplicateFileError,

    /// Uploaded hash not correct
    #[error("File hash that was provided did not match checksum of uploaded file")]
    UploadHashMismatchError,

    /// Upload not allowed
    #[error("Upload not allowed to this directory")]
    UploadForbiddenError,

    /// Any error related to an invalid path (failed to retrieve entry name, unexpected entry type, etc)
    #[error("Invalid path\ncaused by: {0}")]
    InvalidPathError(String),

    /// Might occur if the user has insufficient permissions to create an entry in a given directory
    #[error("Insufficient permissions to create file in {0}")]
    InsufficientPermissionsError(String),

    /// Any error related to parsing
    #[error("Failed to parse {0}\ncaused by: {1}")]
    ParseError(String, String),

    /// Might occur when the creation of an archive fails
    #[error("An error occurred while creating the {0}\ncaused by: {1}")]
    ArchiveCreationError(String, Box<RuntimeError>),

    /// More specific archive creation failure reason
    #[error("{0}")]
    ArchiveCreationDetailError(String),

    /// Might occur when the HTTP credentials are not correct
    #[error("Invalid credentials for HTTP authentication")]
    InvalidHttpCredentials,

    /// Might occur when an HTTP request is invalid
    #[error("Invalid HTTP request\ncaused by: {0}")]
    InvalidHttpRequestError(String),

    /// Might occur when trying to access a page that does not exist
    #[error("Route {0} could not be found")]
    RouteNotFoundError(String),
}

impl IntoResponse for RuntimeError {
    fn into_response(self) -> axum::response::Response {
        use RuntimeError as E;
        use StatusCode as S;

        let res = match self {
            E::IoError(_, _) => S::INTERNAL_SERVER_ERROR,
            E::MultipartError(_) => S::BAD_REQUEST,
            E::DuplicateFileError => S::CONFLICT,
            E::UploadHashMismatchError => S::BAD_REQUEST,
            E::UploadForbiddenError => S::FORBIDDEN,
            E::InvalidPathError(_) => S::BAD_REQUEST,
            E::InsufficientPermissionsError(_) => S::FORBIDDEN,
            E::ParseError(_, _) => S::BAD_REQUEST,
            E::ArchiveCreationError(_, _) => S::INTERNAL_SERVER_ERROR,
            E::ArchiveCreationDetailError(_) => S::INTERNAL_SERVER_ERROR,
            E::InvalidHttpCredentials => S::UNAUTHORIZED,
            E::InvalidHttpRequestError(_) => S::BAD_REQUEST,
            E::RouteNotFoundError(_) => S::NOT_FOUND,
        };
        res.into_response()
    }
}
