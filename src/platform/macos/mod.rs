//! macOS sandbox backend, built on `sandbox-exec` and SBPL profiles.

mod profile;

pub use profile::generate_profile;

use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

use blocking::unblock;

use crate::error::{Error, Result};
use crate::platform::rlimit::PreparedLimits;
use crate::platform::{Backend, Child, SpawnRequest};

/// Absolute path to the system sandbox launcher.
///
/// Resolved absolutely rather than through `PATH`, so the sandbox cannot be
/// side-stepped by an attacker-controlled search path.
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// macOS sandbox backend using `sandbox-exec`.
pub struct MacOSBackend {
    _private: (),
}

impl MacOSBackend {
    /// Create the backend, checking that the OS is new enough.
    pub fn new() -> Result<Self> {
        let version = Self::macos_version()?;
        if version < (10, 15) {
            return Err(Error::UnsupportedPlatformVersion {
                platform: "macOS",
                minimum: "10.15",
                current: format!("{}.{}", version.0, version.1),
            });
        }

        Ok(Self { _private: () })
    }

    /// Read the host's macOS version.
    fn macos_version() -> Result<(u32, u32)> {
        let output = Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .map_err(|e| Error::InitFailed(format!("failed to run sw_vers: {e}")))?;

        if !output.status.success() {
            return Err(Error::InitFailed(format!(
                "sw_vers failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        let version = String::from_utf8_lossy(&output.stdout);
        parse_macos_version(version.trim())
    }

    /// Turn a spawn request into a configured `sandbox-exec` invocation.
    fn build_command(&self, request: &SpawnRequest<'_>) -> Result<Command> {
        let profile = profile::generate_profile(request.config, request.proxy_port)?;

        let mut cmd = Command::new(SANDBOX_EXEC);
        cmd.arg("-p").arg(&profile);
        cmd.arg(request.program);
        cmd.args(request.args);
        cmd.current_dir(request.working_dir());

        // Start from nothing and add back only what was asked for.
        cmd.env_clear();
        for var in request.config.env_passthrough() {
            if let Ok(value) = std::env::var(var) {
                cmd.env(var, value);
            }
        }
        for (key, value) in request.envs {
            cmd.env(key, value);
        }

        // Installing a `pre_exec` hook rules out the `posix_spawn` fast path,
        // so it is only added when there is actually a limit to apply.
        if !request.config.limits().is_empty() {
            let limits = PreparedLimits::new(request.config.limits());
            // SAFETY: the closure only issues `setrlimit`, which is
            // async-signal-safe and allocation-free, as `pre_exec` requires.
            unsafe {
                cmd.pre_exec(move || limits.apply());
            }
        }

        Ok(cmd)
    }
}

impl Backend for MacOSBackend {
    async fn execute(&self, request: SpawnRequest<'_>) -> Result<Output> {
        tracing::debug!(program = %request.program, args = ?request.args, "sandbox: executing");

        let mut cmd = self.build_command(&request)?;
        cmd.stdin(request.stdin);
        cmd.stdout(request.stdout);
        cmd.stderr(request.stderr);

        let output = unblock(move || cmd.output()).await?;

        tracing::debug!(
            program = %request.program,
            exit_code = ?output.status.code(),
            success = output.status.success(),
            "sandbox: command completed"
        );

        Ok(output)
    }

    async fn spawn(&self, request: SpawnRequest<'_>) -> Result<Child> {
        tracing::debug!(program = %request.program, args = ?request.args, "sandbox: spawning");

        let mut cmd = self.build_command(&request)?;
        cmd.stdin(request.stdin);
        cmd.stdout(request.stdout);
        cmd.stderr(request.stderr);
        // Its own process group, so the whole tree can be killed at once.
        cmd.process_group(0);

        let child = cmd.spawn()?;
        tracing::debug!(program = %request.program, pid = child.id(), "sandbox: spawned");

        Ok(Child::new(child))
    }
}

/// Parse the `major.minor` prefix of a macOS version string.
fn parse_macos_version(version: &str) -> Result<(u32, u32)> {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse().ok());
    // Major-only releases such as "26" are reported without a minor component.
    let minor = parts.next().map_or(Some(0), |part| part.parse().ok());

    match (major, minor) {
        (Some(major), Some(minor)) => Ok((major, minor)),
        _ => Err(Error::InitFailed(format!(
            "unrecognized macOS version: {version}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_strings_parse() {
        assert_eq!(parse_macos_version("14.5").unwrap(), (14, 5));
        assert_eq!(parse_macos_version("10.15.7").unwrap(), (10, 15));
        assert_eq!(parse_macos_version("26").unwrap(), (26, 0));
    }

    #[test]
    fn unparseable_versions_are_rejected() {
        assert!(parse_macos_version("").is_err());
        assert!(parse_macos_version("sonoma").is_err());
    }

    #[test]
    fn version_ordering_covers_the_minimum() {
        assert!(parse_macos_version("10.14").unwrap() < (10, 15));
        assert!(parse_macos_version("10.15").unwrap() >= (10, 15));
        assert!(parse_macos_version("11.0").unwrap() >= (10, 15));
    }
}
