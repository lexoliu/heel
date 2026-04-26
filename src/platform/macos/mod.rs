mod profile;

pub use profile::generate_profile;

use std::process::{Command, Output};

use blocking::unblock;

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::platform::{Backend, Child};
use crate::stdio::StdioConfig;

/// macOS sandbox backend using sandbox-exec
pub struct MacOSBackend {
    _private: (),
}

impl MacOSBackend {
    /// Create a new macOS sandbox backend
    pub fn new() -> Result<Self> {
        // Verify macOS version >= 10.15
        let version = Self::get_macos_version()?;
        if version < (10, 15) {
            return Err(Error::UnsupportedPlatformVersion {
                platform: "macOS",
                minimum: "10.15",
                current: format!("{}.{}", version.0, version.1),
            });
        }

        Ok(Self { _private: () })
    }

    fn get_macos_version() -> Result<(u32, u32)> {
        let output = Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .map_err(|e| Error::InitFailed(format!("Failed to get macOS version: {}", e)))?;

        let version_str = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = version_str.trim().split('.').collect();

        if parts.len() < 2 {
            return Err(Error::InitFailed(format!(
                "Invalid macOS version format: {}",
                version_str
            )));
        }

        let major: u32 = parts[0]
            .parse()
            .map_err(|_| Error::InitFailed(format!("Invalid major version: {}", parts[0])))?;
        let minor: u32 = parts[1]
            .parse()
            .map_err(|_| Error::InitFailed(format!("Invalid minor version: {}", parts[1])))?;

        Ok((major, minor))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_command(
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
    ) -> Result<Command> {
        // Generate SBPL profile
        let sbpl_profile = profile::generate_profile(config, proxy_port)?;

        tracing::debug!("Generated SBPL profile:\n{}", sbpl_profile);

        // Build command with sandbox-exec
        let mut cmd = Command::new("sandbox-exec");
        cmd.arg("-p").arg(&sbpl_profile);
        cmd.arg(program);
        cmd.args(args);

        // Set working directory
        let work_dir = current_dir.unwrap_or(config.working_dir());
        cmd.current_dir(work_dir);

        // Clear environment and set allowed vars
        cmd.env_clear();
        for var in config.env_passthrough() {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }

        // Add custom environment variables (includes proxy vars from Command)
        for (key, val) in envs {
            cmd.env(key, val);
        }

        // Set stdio
        cmd.stdin(std::process::Stdio::from(stdin));
        cmd.stdout(std::process::Stdio::from(stdout));
        cmd.stderr(std::process::Stdio::from(stderr));

        Ok(cmd)
    }
}

impl Backend for MacOSBackend {
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
            program,
            args,
            envs,
            current_dir,
            stdin,
            stdout,
            stderr,
        )?;

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
            program,
            args,
            envs,
            current_dir,
            stdin,
            stdout,
            stderr,
        )?;

        let child = cmd.spawn()?;

        tracing::debug!(program = %program, pid = child.id(), "sandbox: command spawned");

        Ok(Child::new(child))
    }
}
