use std::ffi::OsStr;
use std::future::Future;
use std::path::Path;
use std::process::Output;

use crate::command::StdioConfig;
use crate::config::SandboxConfigData;
use crate::error::Result;
pub use child::Child;

/// Whether two environment variable names are equal under host rules.
///
/// Windows compares names case-insensitively; other supported platforms treat
/// distinct cases as distinct variables.
pub(crate) fn env_name_eq(name: impl AsRef<OsStr>, expected: impl AsRef<OsStr>) -> bool {
    let name = name.as_ref().as_encoded_bytes();
    let expected = expected.as_ref().as_encoded_bytes();
    #[cfg(windows)]
    {
        name.eq_ignore_ascii_case(expected)
    }
    #[cfg(not(windows))]
    {
        name == expected
    }
}

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

pub(crate) mod child;

pub(crate) mod unresolved;

#[cfg(unix)]
pub(crate) mod preexec;

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
    ///
    /// macOS bakes it into the profile generated with the sandbox.
    #[cfg_attr(target_os = "macos", expect(dead_code))]
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
pub(crate) fn create_native_backend(
    config: &SandboxConfigData,
    proxy_port: Option<u16>,
) -> Result<NativeBackend> {
    NativeBackend::new(config, proxy_port)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(crate) fn create_native_backend(
    _config: &SandboxConfigData,
    _proxy_port: Option<u16>,
) -> Result<std::convert::Infallible> {
    Err(crate::error::Error::UnsupportedPlatform)
}

/// Reject the settings the Windows backend cannot enforce.
///
/// An AppContainer token is default-deny and only ACL entries naming its SID
/// open anything, so "the whole filesystem is writable" would mean rewriting
/// the ACL of every drive root and everything beneath it. That is neither
/// possible without administrator rights nor something a sandbox may do to the
/// host, so the setting is refused rather than run as if it were strict.
///
/// The host protection policies are enforced by the macOS and Linux backends
/// only. A sandbox that carried one here would run with a weaker boundary than
/// the caller wrote down, so it is refused too.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn require_windows_support(config: &SandboxConfigData) -> Result<()> {
    let refused = if config.writable_file_system() {
        Some("writable_file_system")
    } else if config.read_denylist().is_some() {
        Some("the credential read denylist")
    } else if config.write_denylist().is_some() {
        Some("the persistence write denylist")
    } else {
        None
    };
    match refused {
        Some(setting) => Err(crate::error::Error::UnsupportedSetting {
            setting,
            platform: "windows",
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_refuses_a_writable_file_system() {
        let config = crate::SandboxConfig::builder()
            .writable_file_system(true)
            .build();
        let error = require_windows_support(config.data()).expect_err("must be refused");
        assert!(matches!(
            error,
            crate::error::Error::UnsupportedSetting {
                setting: "writable_file_system",
                platform: "windows"
            }
        ));
        assert_eq!(
            error.to_string(),
            "writable_file_system is not supported on windows, and a sandbox is never built without it"
        );
    }

    #[test]
    fn windows_refuses_the_host_protection_policies() {
        let configs = [
            crate::SandboxConfig::builder()
                .read_denylist(crate::ReadDenylist::credentials())
                .build(),
            crate::SandboxConfig::builder()
                .write_denylist(crate::WriteDenylist::persistence())
                .build(),
        ];
        for config in configs {
            let error = require_windows_support(config.data()).expect_err("must be refused");
            assert!(matches!(
                error,
                crate::error::Error::UnsupportedSetting {
                    platform: "windows",
                    ..
                }
            ));
        }
    }

    #[test]
    fn windows_accepts_every_other_filesystem_configuration() {
        for strict in [true, false] {
            let config = crate::SandboxConfig::builder()
                .filesystem_strict(strict)
                .build();
            require_windows_support(config.data()).expect("supported");
        }
    }

    #[test]
    fn environment_names_match_under_host_rules() {
        assert!(env_name_eq("PATH", "PATH"));
        assert!(!env_name_eq("PATH", "PATHEXT"));

        #[cfg(windows)]
        assert!(env_name_eq("Path", "PATH"));
        #[cfg(not(windows))]
        assert!(!env_name_eq("Path", "PATH"));
    }
}
