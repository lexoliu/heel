//! Linux sandbox backend, built on Landlock and Seccomp.

mod landlock_rules;
mod seccomp_filter;

use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

use blocking::unblock;

use crate::error::{Error, Result};
use crate::platform::rlimit::PreparedLimits;
use crate::platform::{Backend, Child, SpawnRequest};

/// Lowest kernel version with Landlock ABI v4.
const MIN_KERNEL_VERSION: KernelVersion = KernelVersion::new(6, 7, 0);

/// Linux sandbox backend using Landlock for files and network, Seccomp for
/// syscalls.
pub struct LinuxBackend {
    _private: (),
}

/// A parsed kernel release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct KernelVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl KernelVersion {
    const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse the numeric prefix of a release string such as `6.8.1-generic`.
    fn parse(release: &str) -> Result<Self> {
        let numeric = release.split('-').next().unwrap_or(release);
        let mut parts = numeric.split('.');

        let major = parts.next().and_then(|part| part.parse().ok());
        let minor = parts.next().and_then(|part| part.parse().ok());
        let patch = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);

        match (major, minor) {
            (Some(major), Some(minor)) => Ok(Self::new(major, minor, patch)),
            _ => Err(Error::InitFailed(format!(
                "unrecognized kernel version: {release}"
            ))),
        }
    }
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl LinuxBackend {
    /// Create the backend, verifying that the kernel can enforce the sandbox.
    ///
    /// Both checks are cheap syscalls. In particular, support is probed by
    /// creating a ruleset rather than by forking a child and applying one:
    /// forking a multi-threaded process and then allocating in the child is
    /// unsound.
    pub fn new() -> Result<Self> {
        let kernel = detect_kernel_version()?;
        if kernel < MIN_KERNEL_VERSION {
            return Err(Error::UnsupportedPlatformVersion {
                platform: "Linux",
                minimum: "6.7",
                current: kernel.to_string(),
            });
        }

        landlock_rules::probe_support()?;

        tracing::info!(%kernel, "Linux sandbox backend initialized");
        Ok(Self { _private: () })
    }

    /// Turn a spawn request into a configured command.
    fn build_command(&self, request: &SpawnRequest<'_>) -> Result<Command> {
        // Both are built here, on the host, so that the post-fork path only
        // issues syscalls.
        let ruleset = landlock_rules::build_ruleset(request.config, request.proxy_port)?;
        let allow_tcp = request.proxy_port.is_some() || request.config.ipc_socket().is_some();
        let filter = seccomp_filter::build_filter(allow_tcp)?;
        let limits = PreparedLimits::new(request.config.limits());

        let mut cmd = Command::new(request.program);
        cmd.args(request.args);
        cmd.current_dir(request.working_dir());

        cmd.env_clear();
        for var in request.config.env_passthrough() {
            if let Ok(value) = std::env::var(var) {
                cmd.env(var, value);
            }
        }
        for (key, value) in request.envs {
            cmd.env(key, value);
        }

        let mut ruleset = Some(ruleset);
        let mut filter = Some(filter);

        // SAFETY: the closure only applies pre-built rulesets and filters and
        // installs resource limits, all of which are plain syscalls. Nothing
        // here allocates or takes a lock, as `pre_exec` requires.
        unsafe {
            cmd.pre_exec(move || {
                limits.apply()?;

                // Both values are consumed on first use; a second call would
                // mean the command was spawned twice from one builder, which
                // must fail rather than silently run unsandboxed.
                ruleset
                    .take()
                    .ok_or_else(|| std::io::Error::other("Landlock ruleset already applied"))?
                    .restrict_self()?;

                filter
                    .take()
                    .ok_or_else(|| std::io::Error::other("seccomp filter already applied"))?
                    .apply()?;

                Ok(())
            });
        }

        Ok(cmd)
    }
}

/// Where the kernel publishes its release string.
const KERNEL_RELEASE_PATH: &str = "/proc/sys/kernel/osrelease";

/// Read the running kernel's version.
///
/// Read from procfs rather than through `uname`, which keeps this free of both
/// a dependency and an unsafe block for a value the kernel already exposes as
/// text.
fn detect_kernel_version() -> Result<KernelVersion> {
    let release = std::fs::read_to_string(KERNEL_RELEASE_PATH)
        .map_err(|error| Error::path(KERNEL_RELEASE_PATH, error))?;
    KernelVersion::parse(release.trim())
}

impl Backend for LinuxBackend {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_versions_parse() {
        assert_eq!(
            KernelVersion::parse("6.7.0").unwrap(),
            KernelVersion::new(6, 7, 0)
        );
        assert_eq!(
            KernelVersion::parse("6.8.1-generic").unwrap(),
            KernelVersion::new(6, 8, 1)
        );
        assert_eq!(
            KernelVersion::parse("5.15.0-91-generic").unwrap(),
            KernelVersion::new(5, 15, 0)
        );
        assert_eq!(
            KernelVersion::parse("6.12").unwrap(),
            KernelVersion::new(6, 12, 0)
        );
    }

    #[test]
    fn unparsable_kernel_versions_are_rejected() {
        assert!(KernelVersion::parse("").is_err());
        assert!(KernelVersion::parse("linux").is_err());
    }

    #[test]
    fn kernel_versions_order_by_component() {
        assert!(KernelVersion::new(6, 7, 0) >= MIN_KERNEL_VERSION);
        assert!(KernelVersion::new(6, 8, 0) > MIN_KERNEL_VERSION);
        assert!(KernelVersion::new(5, 15, 0) < MIN_KERNEL_VERSION);
        assert!(KernelVersion::new(6, 6, 9) < MIN_KERNEL_VERSION);
    }
}
