use napi::bindgen_prelude::*;

/// Convert a heel error into a NAPI error with a descriptive code.
///
/// `heel::Error` is `#[non_exhaustive]`, so the match needs a wildcard arm;
/// every variant known today is listed so each keeps its own code.
pub fn convert_error(err: heel::Error) -> Error {
    let code = match &err {
        heel::Error::UnsupportedPlatform => "ERR_UNSUPPORTED_PLATFORM",
        heel::Error::UnsupportedPlatformVersion { .. } => "ERR_UNSUPPORTED_PLATFORM_VERSION",
        heel::Error::UnsupportedSetting { .. } => "ERR_UNSUPPORTED_SETTING",
        heel::Error::InitFailed(_) => "ERR_INIT_FAILED",
        heel::Error::PtraceScopeTooStrict { .. } => "ERR_PTRACE_SCOPE",
        heel::Error::SeccompNotifyUnavailable(_) => "ERR_SECCOMP_NOTIFY_UNAVAILABLE",
        heel::Error::NotEnforced(_) => "ERR_NOT_ENFORCED",
        heel::Error::InvalidProfile(_) => "ERR_INVALID_PROFILE",
        heel::Error::Path { .. } => "ERR_PATH",
        heel::Error::GrantRedirected { .. } => "ERR_GRANT_REDIRECTED",
        heel::Error::WorkingDir { .. } => "ERR_WORKING_DIR",
        heel::Error::PythonNotFound => "ERR_PYTHON_NOT_FOUND",
        heel::Error::VenvNotFound(_) => "ERR_VENV_NOT_FOUND",
        heel::Error::VenvCreationFailed(_) => "ERR_VENV_CREATION",
        heel::Error::PackageInstallFailed(_) => "ERR_PACKAGE_INSTALL",
        heel::Error::Proxy(_) => "ERR_PROXY",
        heel::Error::AuditLog(_) => "ERR_AUDIT_LOG",
        heel::Error::Template(_) => "ERR_TEMPLATE",
        heel::Error::Io(_) => "ERR_IO",
        heel::Error::Ipc(_) => "ERR_IPC",
        heel::Error::Pty(_) => "ERR_PTY",
        _ => "ERR_UNKNOWN",
    };

    Error::new(Status::GenericFailure, format!("[{code}] {err}"))
}

/// Extension trait for converting heel results to NAPI results.
pub trait IntoNapiResult<T> {
    fn into_napi(self) -> Result<T>;
}

impl<T> IntoNapiResult<T> for heel::Result<T> {
    fn into_napi(self) -> Result<T> {
        self.map_err(convert_error)
    }
}
