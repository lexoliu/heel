use std::io;
use std::path::PathBuf;
use thiserror::Error;

use crate::ipc::IpcError;

/// Result type for sandbox operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during sandbox operations.
#[derive(Error, Debug)]
#[non_exhaustive]
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

    /// The configuration asks for a setting this platform's backend cannot enforce.
    ///
    /// Raised when the sandbox is constructed, so that a boundary the caller
    /// wrote down is never silently weaker than the one that runs.
    #[error("{setting} is not supported on {platform}, and a sandbox is never built without it")]
    UnsupportedSetting {
        /// The setting that cannot be enforced.
        setting: &'static str,
        /// The platform that cannot enforce it.
        platform: &'static str,
    },

    /// The backend could not be initialized.
    #[error("sandbox initialization failed: {0}")]
    InitFailed(String),

    /// Yama's `kernel.yama.ptrace_scope` forbids the broker from reading the
    /// memory of the processes it serves.
    ///
    /// A host precondition: an administrator lowers the setting, the sandbox
    /// cannot.
    #[error(
        "kernel.yama.ptrace_scope is {scope}, but the sandbox broker needs {max} or lower; \
         lower it with `sysctl kernel.yama.ptrace_scope={max}`"
    )]
    PtraceScopeTooStrict {
        /// The value the host reports.
        scope: u8,
        /// The highest value the broker works under.
        max: u8,
    },

    /// The kernel does not offer seccomp user notification, which the broker
    /// is built on.
    ///
    /// A host precondition: typically a kernel built without it, or a container
    /// runtime whose seccomp policy blocks the `seccomp` syscall.
    #[error("seccomp user notification is unavailable on this host: {0}")]
    SeccompNotifyUnavailable(io::Error),

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

    /// A granted path reaches a symbolic link, or a Windows junction.
    ///
    /// A grant names a path the caller has already resolved, and the sandbox
    /// never follows a link to honour it: a component that has become a link
    /// since the caller resolved the path would redirect the grant to the
    /// link's target, so the build is refused and nothing is granted.
    #[error("granted path {path} passes through a symbolic link")]
    GrantRedirected {
        /// The granted path, as the caller configured it.
        path: PathBuf,
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
