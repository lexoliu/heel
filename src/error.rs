use std::io;
use std::path::PathBuf;
use thiserror::Error;

use crate::ipc::IpcError;

/// Result type for sandbox operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during sandbox operations.
#[derive(Error, Debug)]
pub enum Error {
    /// The host platform has no sandbox backend.
    #[error("unsupported platform")]
    UnsupportedPlatform,

    /// The host platform is supported but too old.
    #[error("platform {platform} requires version {minimum}, found {current}")]
    UnsupportedPlatformVersion {
        /// Platform name.
        platform: &'static str,
        /// Lowest supported version.
        minimum: &'static str,
        /// Version detected on this host.
        current: String,
    },

    /// The backend could not be initialized.
    #[error("sandbox initialization failed: {0}")]
    InitFailed(String),

    /// The kernel accepted the request but would not enforce the sandbox.
    #[error("sandbox not enforced: {0}")]
    NotEnforced(String),

    /// The generated sandbox profile is invalid.
    #[error("invalid sandbox profile: {0}")]
    InvalidProfile(String),

    /// A configured path could not be used.
    #[error("cannot use path {path}: {source}")]
    Path {
        /// The path that failed.
        path: PathBuf,
        /// Underlying I/O failure.
        source: io::Error,
    },

    /// The working directory could not be prepared or removed.
    #[error("cannot prepare working directory {path}: {source}")]
    WorkingDir {
        /// The working directory path.
        path: PathBuf,
        /// Underlying I/O failure.
        source: io::Error,
    },

    /// No Python interpreter was found on the host.
    #[error("python not found on system")]
    PythonNotFound,

    /// The configured virtual environment is missing or incomplete.
    #[error("python venv not found at: {0}")]
    VenvNotFound(PathBuf),

    /// Creating the virtual environment failed.
    #[error("python venv creation failed: {0}")]
    VenvCreationFailed(String),

    /// Installing packages into the virtual environment failed.
    #[error("package installation failed: {0}")]
    PackageInstallFailed(String),

    /// The network proxy failed.
    #[error("network proxy error: {0}")]
    Proxy(String),

    /// The network audit log failed.
    #[error("network audit log error: {0}")]
    AuditLog(String),

    /// Rendering a profile or wrapper template failed.
    #[error("template render failed: {0}")]
    Template(#[from] askama::Error),

    /// An I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// An IPC operation failed.
    #[error("IPC error: {0}")]
    Ipc(#[from] IpcError),

    /// A pseudo-terminal operation failed.
    #[error("PTY error: {0}")]
    Pty(String),
}

impl Error {
    /// Attach a path to an I/O failure.
    pub(crate) fn path(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Path {
            path: path.into(),
            source,
        }
    }
}
