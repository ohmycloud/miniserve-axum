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
