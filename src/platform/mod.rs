use std::future::Future;
use std::path::Path;
use std::process::Output;

use crate::command::StdioConfig;
use crate::config::SandboxConfigData;
use crate::error::Result;
pub use child::Child;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

pub(crate) mod child;

#[cfg(unix)]
pub(crate) mod rlimit;

#[cfg(target_os = "windows")]
pub mod windows;

/// Everything a backend needs to launch one sandboxed process.
///
/// Backends take a large, fixed set of inputs; passing them as a struct keeps
/// the trait readable and lets callers build a request once and reuse the
/// shape for both `execute` and `spawn`.
///
/// Only an implemented backend reads these; Windows has none yet and refuses to
/// construct, so every field is legitimately unread there. The allow is scoped
/// to that target so a genuinely unused field still fails the build elsewhere.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) struct SpawnRequest<'a> {
    /// Policy-independent sandbox configuration.
    pub config: &'a SandboxConfigData,
    /// Port of the sandbox proxy, when network access is enabled.
    pub proxy_port: Option<u16>,
    /// Program to run.
    pub program: &'a str,
    /// Arguments for the program.
    pub args: &'a [String],
    /// The complete environment for the process.
    pub envs: &'a [(String, String)],
    /// Working directory override; defaults to the sandbox working directory.
    pub current_dir: Option<&'a Path>,
    /// Standard input configuration.
    ///
    /// Carried as the crate's own type rather than a `std::process::Stdio`,
    /// which is opaque: the Windows backend does not spawn through
    /// `std::process` and has to know what was asked for.
    pub stdin: StdioConfig,
    /// Standard output configuration.
    pub stdout: StdioConfig,
    /// Standard error configuration.
    pub stderr: StdioConfig,
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
impl SpawnRequest<'_> {
    /// The directory the process starts in.
    pub(crate) fn working_dir(&self) -> &Path {
        self.current_dir.unwrap_or(self.config.working_dir())
    }
}

/// Internal trait for platform-specific sandbox backends.
pub(crate) trait Backend: Sized + Send + Sync {
    /// Run a command to completion and collect its output.
    fn execute(&self, request: SpawnRequest<'_>) -> impl Future<Output = Result<Output>> + Send;

    /// Spawn a command as a child process.
    fn spawn(&self, request: SpawnRequest<'_>) -> impl Future<Output = Result<Child>> + Send;
}

/// The backend for the current platform.
#[cfg(target_os = "macos")]
pub(crate) type NativeBackend = macos::MacOSBackend;

/// The backend for the current platform.
#[cfg(target_os = "linux")]
pub(crate) type NativeBackend = linux::LinuxBackend;

/// The backend for the current platform.
#[cfg(target_os = "windows")]
pub(crate) type NativeBackend = windows::WindowsBackend;

/// Create the native backend for the current platform.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub(crate) fn create_native_backend() -> Result<NativeBackend> {
    NativeBackend::new()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(crate) fn create_native_backend() -> Result<std::convert::Infallible> {
    Err(crate::error::Error::UnsupportedPlatform)
}
