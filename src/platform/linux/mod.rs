//! Linux sandbox backend using Landlock + Seccomp

mod landlock_rules;
mod seccomp_filter;

use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

use blocking::unblock;

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::platform::linux::landlock_rules::LandlockConfig;
use crate::platform::{Backend, Child};
use crate::stdio::StdioConfig;

/// Minimum required kernel version for full security (Landlock ABI v4)
const MIN_KERNEL_VERSION: KernelVersion = KernelVersion::new(6, 7, 0);

/// Minimum required Landlock ABI version (v4 adds network restrictions)
const MIN_LANDLOCK_ABI: i32 = 4;

fn pre_exec_write(msg: &[u8]) {
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr() as *const _, msg.len());
    }
}

/// Linux sandbox backend using Landlock (filesystem + network) and Seccomp (syscall filtering)
pub struct LinuxBackend {
    _private: (),
}

struct CommandLaunch<'a> {
    program: &'a str,
    args: &'a [String],
    envs: &'a [(String, String)],
    current_dir: Option<&'a std::path::Path>,
    stdin: StdioConfig,
    stdout: StdioConfig,
    stderr: StdioConfig,
}

/// Parsed kernel version
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

    fn parse(release: &str) -> Result<Self> {
        // Parse "6.7.0-generic" or "6.7.0" -> (6, 7, 0)
        let version_part = release.split('-').next().unwrap_or(release);
        let parts: Vec<&str> = version_part.split('.').collect();

        if parts.len() < 2 {
            return Err(Error::InitFailed(format!(
                "Invalid kernel version format: {}",
                release
            )));
        }

        let major: u32 = parts[0]
            .parse()
            .map_err(|_| Error::InitFailed(format!("Invalid major version: {}", parts[0])))?;
        let minor: u32 = parts[1]
            .parse()
            .map_err(|_| Error::InitFailed(format!("Invalid minor version: {}", parts[1])))?;
        let patch: u32 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl LinuxBackend {
    /// Create a new Linux sandbox backend
    ///
    /// Fails if:
    /// - Kernel version < 6.7 (required for Landlock ABI v4)
    /// - Landlock is not available or ABI < v4
    pub fn new() -> Result<Self> {
        // Check kernel version
        let kernel_version = Self::detect_kernel_version()?;
        if kernel_version < MIN_KERNEL_VERSION {
            return Err(Error::UnsupportedPlatformVersion {
                platform: "Linux",
                minimum: "6.7",
                current: kernel_version.to_string(),
            });
        }

        // Check Landlock ABI version
        let landlock_abi = Self::detect_landlock_abi()?;
        if landlock_abi < MIN_LANDLOCK_ABI {
            return Err(Error::UnsupportedPlatformVersion {
                platform: "Linux (Landlock ABI)",
                minimum: "4",
                current: landlock_abi.to_string(),
            });
        }

        tracing::info!(
            kernel = %kernel_version,
            landlock_abi = landlock_abi,
            "Linux sandbox backend initialized"
        );

        Ok(Self { _private: () })
    }

    fn detect_kernel_version() -> Result<KernelVersion> {
        let utsname = nix::sys::utsname::uname()
            .map_err(|e| Error::InitFailed(format!("uname failed: {}", e)))?;
        let release = utsname.release().to_string_lossy();
        KernelVersion::parse(&release)
    }

    fn detect_landlock_abi() -> Result<i32> {
        use landlock::{ABI, Access, RulesetAttr};

        // Try to detect the best available ABI
        // We test by creating a ruleset - restrict_self() is tested in a forked child
        // to avoid restricting the main process
        let abi = ABI::V4; // We require V4

        // Create a minimal ruleset to check if this ABI is supported
        let ruleset =
            match landlock::Ruleset::default().handle_access(landlock::AccessFs::from_all(abi)) {
                Ok(r) => r,
                Err(_) => {
                    // Try to detect what version is actually available
                    return if landlock::Ruleset::default()
                        .handle_access(landlock::AccessFs::from_all(ABI::V3))
                        .is_ok()
                    {
                        Err(Error::UnsupportedPlatformVersion {
                            platform: "Linux (Landlock ABI)",
                            minimum: "4",
                            current: "3".to_string(),
                        })
                    } else if landlock::Ruleset::default()
                        .handle_access(landlock::AccessFs::from_all(ABI::V2))
                        .is_ok()
                    {
                        Err(Error::UnsupportedPlatformVersion {
                            platform: "Linux (Landlock ABI)",
                            minimum: "4",
                            current: "2".to_string(),
                        })
                    } else if landlock::Ruleset::default()
                        .handle_access(landlock::AccessFs::from_all(ABI::V1))
                        .is_ok()
                    {
                        Err(Error::UnsupportedPlatformVersion {
                            platform: "Linux (Landlock ABI)",
                            minimum: "4",
                            current: "1".to_string(),
                        })
                    } else {
                        Err(Error::NotEnforced("Landlock not available in kernel"))
                    };
                }
            };

        // Actually create the ruleset to verify it works
        let _created = ruleset.create().map_err(|e| {
            Error::NotEnforced(Box::leak(
                format!("Landlock ruleset creation failed: {}", e).into_boxed_str(),
            ))
        })?;

        // Test restrict_self() in a forked child process to avoid restricting the main process
        // This is critical because Landlock restrictions are inherited by child processes
        // We must test with actual path rules, not just an empty ruleset
        match unsafe { libc::fork() } {
            -1 => Err(Error::InitFailed(
                "fork failed for Landlock test".to_string(),
            )),
            0 => {
                // Child process - test restrict_self() with real rules and exit with status code
                use landlock::{PathBeneath, PathFd, RulesetCreatedAttr, RulesetStatus};

                let test_ruleset = landlock::Ruleset::default()
                    .handle_access(landlock::AccessFs::from_all(ABI::V4))
                    .and_then(|r| r.create());

                let exit_code = match test_ruleset {
                    Ok(r) => {
                        // Add at least one real path rule to properly test Landlock functionality
                        // An empty ruleset might succeed even when Landlock isn't working
                        let r = if let Ok(path_fd) = PathFd::new("/tmp") {
                            match r.add_rule(PathBeneath::new(
                                path_fd,
                                landlock::AccessFs::from_all(ABI::V4),
                            )) {
                                Ok(r) => r,
                                Err(_) => {
                                    unsafe { libc::_exit(1) };
                                }
                            }
                        } else {
                            r
                        };

                        match r.restrict_self() {
                            Ok(status) => match status.ruleset {
                                RulesetStatus::FullyEnforced => 0,
                                RulesetStatus::PartiallyEnforced => 2,
                                RulesetStatus::NotEnforced => 3,
                            },
                            Err(_) => 1, // restrict_self failed
                        }
                    }
                    Err(_) => 1,
                };
                unsafe { libc::_exit(exit_code) };
            }
            pid => {
                // Parent process - wait for child and check result
                let mut status: libc::c_int = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };

                if libc::WIFEXITED(status) {
                    match libc::WEXITSTATUS(status) {
                        0 => Ok(4), // FullyEnforced
                        1 => Err(Error::NotEnforced(
                            "Landlock restrict_self failed - kernel may not support Landlock",
                        )),
                        2 => Err(Error::NotEnforced(
                            "Landlock only partially enforced - refusing to run with reduced security",
                        )),
                        3 => Err(Error::NotEnforced("Landlock not enforced by kernel")),
                        _ => Err(Error::InitFailed(
                            "Landlock test child exited with unexpected status".to_string(),
                        )),
                    }
                } else {
                    Err(Error::InitFailed(
                        "Landlock test child terminated abnormally".to_string(),
                    ))
                }
            }
        }
    }

    fn build_command(
        &self,
        config: &SandboxConfigData,
        proxy_port: u16,
        launch: CommandLaunch<'_>,
    ) -> Result<Command> {
        // Build Landlock ruleset (validated at creation time)
        let landlock_config = LandlockConfig::from_config(config);
        let landlock_ruleset = landlock_rules::build_ruleset(&landlock_config, proxy_port)?;

        // Build Seccomp BPF filter
        let security = config.security().clone();
        let seccomp_filter = seccomp_filter::build_filter(
            &security,
            config.network_deny_all(),
            config.ipc_port().is_some(),
        )?;

        let mut cmd = Command::new(launch.program);
        cmd.args(launch.args);

        // Set working directory
        let work_dir = launch.current_dir.unwrap_or(config.working_dir());
        cmd.current_dir(work_dir);

        // Clear environment and set allowed vars
        cmd.env_clear();
        for var in config.env_passthrough() {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }

        // Add custom environment variables (includes proxy vars from Command)
        for (key, val) in launch.envs {
            cmd.env(key, val);
        }

        // Set stdio
        cmd.stdin(std::process::Stdio::from(launch.stdin));
        cmd.stdout(std::process::Stdio::from(launch.stdout));
        cmd.stderr(std::process::Stdio::from(launch.stderr));

        // CRITICAL: Apply sandbox restrictions after fork, before exec
        // Keep pre_exec minimal and async-signal-safe: only apply pre-built rulesets/filters.
        let mut landlock_ruleset = Some(landlock_ruleset);
        let mut seccomp_filter = Some(seccomp_filter);

        unsafe {
            cmd.pre_exec(move || {
                #[cfg(debug_assertions)]
                pre_exec_write(b"heel: pre_exec start\n");

                let ruleset = landlock_ruleset
                    .take()
                    .ok_or_else(|| std::io::Error::other("Landlock ruleset already used"))?;

                if let Err(err) = ruleset.restrict_self() {
                    pre_exec_write(b"heel: landlock restrict_self failed\n");
                    let errno = err
                        .raw_os_error()
                        .map(|code| format!(" (errno {code})"))
                        .unwrap_or_default();
                    return Err(std::io::Error::new(
                        err.kind(),
                        format!("landlock restrict_self failed: {err}{errno}"),
                    ));
                }

                #[cfg(debug_assertions)]
                pre_exec_write(b"heel: landlock applied\n");

                let filter = seccomp_filter
                    .take()
                    .ok_or_else(|| std::io::Error::other("Seccomp filter already used"))?;

                if let Err(err) = filter.apply() {
                    pre_exec_write(b"heel: seccomp apply failed\n");
                    let errno = err
                        .raw_os_error()
                        .map(|code| format!(" (errno {code})"))
                        .unwrap_or_default();
                    return Err(std::io::Error::new(
                        err.kind(),
                        format!("seccomp apply failed: {err}{errno}"),
                    ));
                }

                #[cfg(debug_assertions)]
                pre_exec_write(b"heel: seccomp applied\n");

                Ok(())
            });
        }

        Ok(cmd)
    }
}

impl Backend for LinuxBackend {
    async fn execute(
        &self,
        config: &SandboxConfigData,
        proxy_port: u16,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        current_dir: Option<&std::path::Path>,
        stdin: StdioConfig,
        stdout: StdioConfig,
        stderr: StdioConfig,
    ) -> Result<Output> {
        tracing::debug!(program = %program, args = ?args, "sandbox: executing command");

        let mut cmd = self.build_command(
            config,
            proxy_port,
            CommandLaunch {
                program,
                args,
                envs,
                current_dir,
                stdin,
                stdout,
                stderr,
            },
        )?;

        // DEBUG: Print command details before spawn
        tracing::info!(
            program = %program,
            args = ?args,
            working_dir = ?current_dir.map(|p| p.display()),
            config_working_dir = %config.working_dir().display(),
            "About to spawn command"
        );

        let output = unblock(move || cmd.output()).await?;

        tracing::debug!(
            program = %program,
            exit_code = ?output.status.code(),
            success = output.status.success(),
            "sandbox: command completed"
        );

        Ok(output)
    }

    async fn spawn(
        &self,
        config: &SandboxConfigData,
        proxy_port: u16,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        current_dir: Option<&std::path::Path>,
        stdin: StdioConfig,
        stdout: StdioConfig,
        stderr: StdioConfig,
    ) -> Result<Child> {
        tracing::debug!(program = %program, args = ?args, "sandbox: spawning command");

        let mut cmd = self.build_command(
            config,
            proxy_port,
            CommandLaunch {
                program,
                args,
                envs,
                current_dir,
                stdin,
                stdout,
                stderr,
            },
        )?;

        let child = cmd.spawn()?;

        tracing::debug!(program = %program, pid = child.id(), "sandbox: command spawned");

        Ok(Child::new(child))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_version_parsing() {
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
    }

    #[test]
    fn test_kernel_version_comparison() {
        assert!(KernelVersion::new(6, 7, 0) >= KernelVersion::new(6, 7, 0));
        assert!(KernelVersion::new(6, 8, 0) > KernelVersion::new(6, 7, 0));
        assert!(KernelVersion::new(5, 15, 0) < KernelVersion::new(6, 7, 0));
    }
}
