use napi::bindgen_prelude::*;

/// Convert heel errors to NAPI errors with descriptive codes
pub fn convert_error(err: heel::Error) -> Error {
    let (code, message) = match &err {
        heel::Error::UnsupportedPlatform => ("ERR_UNSUPPORTED_PLATFORM", err.to_string()),
        heel::Error::UnsupportedPlatformVersion { .. } => {
            ("ERR_UNSUPPORTED_PLATFORM_VERSION", err.to_string())
        }
        heel::Error::InitFailed(msg) => ("ERR_INIT_FAILED", msg.clone()),
        heel::Error::NotEnforced(msg) => ("ERR_NOT_ENFORCED", msg.to_string()),
        heel::Error::PartialEnforcement(msg) => ("ERR_PARTIAL_ENFORCEMENT", msg.to_string()),
        heel::Error::InvalidProfile(msg) => ("ERR_INVALID_PROFILE", msg.clone()),
        heel::Error::PathNotFound(path) => (
            "ERR_PATH_NOT_FOUND",
            format!("Path not found: {}", path.display()),
        ),
        heel::Error::PythonNotFound => ("ERR_PYTHON_NOT_FOUND", err.to_string()),
        heel::Error::VenvNotFound(path) => (
            "ERR_VENV_NOT_FOUND",
            format!("Venv not found: {}", path.display()),
        ),
        heel::Error::VenvCreationFailed(msg) => ("ERR_VENV_CREATION", msg.clone()),
        heel::Error::PackageInstallFailed(msg) => ("ERR_PACKAGE_INSTALL", msg.clone()),
        heel::Error::ProxyError(msg) => ("ERR_PROXY", msg.clone()),
        heel::Error::ProcessError(e) => ("ERR_PROCESS", e.to_string()),
        heel::Error::CommandFailed { code, message } => (
            "ERR_COMMAND_FAILED",
            format!("Exit code {}: {}", code, message),
        ),
        heel::Error::ConfigError(msg) => ("ERR_CONFIG", msg.clone()),
        heel::Error::FfiError(msg) => ("ERR_FFI", msg.clone()),
        heel::Error::IoError(msg) => ("ERR_IO", msg.clone()),
        heel::Error::IpcError(e) => ("ERR_IPC", e.to_string()),
        heel::Error::PtyError(msg) => ("ERR_PTY", msg.clone()),
    };

    Error::new(Status::GenericFailure, format!("[{}] {}", code, message))
}

/// Extension trait for converting heel Results to NAPI Results
pub trait IntoNapiResult<T> {
    fn into_napi(self) -> Result<T>;
}

impl<T> IntoNapiResult<T> for heel::Result<T> {
    fn into_napi(self) -> Result<T> {
        self.map_err(convert_error)
    }
}
