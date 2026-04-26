use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};

use crate::config::SandboxConfigData;
use crate::error::Result;
use crate::network::NetworkPolicy;
use crate::network::NetworkProxy;
use crate::platform::{Backend, Child};
use crate::sandbox::ProcessTracker;
use crate::stdio::StdioConfig;

#[cfg(target_os = "macos")]
type NativeBackend = crate::platform::macos::MacOSBackend;

#[cfg(target_os = "linux")]
type NativeBackend = crate::platform::linux::LinuxBackend;

#[cfg(target_os = "windows")]
type NativeBackend = crate::platform::windows::WindowsBackend;

/// A builder for sandboxed commands, similar to smol::process::Command
///
/// All network traffic from the command is routed through the sandbox's proxy.
/// HTTP_PROXY and HTTPS_PROXY environment variables are automatically injected.
/// If IPC is configured, HEEL_IPC_ENDPOINT is also injected.
pub struct Command<'a> {
    config: &'a SandboxConfigData,
    backend: &'a NativeBackend,
    process_tracker: &'a ProcessTracker,
    proxy_url: Option<String>,
    proxy_port: u16,
    ipc_endpoint: Option<String>,
    program: String,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    current_dir: Option<PathBuf>,
    stdin: StdioConfig,
    stdout: StdioConfig,
    stderr: StdioConfig,
}

impl<'a> Command<'a> {
    /// Create a new command builder (internal use)
    pub(crate) fn new<N: NetworkPolicy>(
        config: &'a SandboxConfigData,
        backend: &'a NativeBackend,
        process_tracker: &'a ProcessTracker,
        proxy: Option<&NetworkProxy<N>>,
        ipc_endpoint: Option<String>,
        program: impl Into<String>,
    ) -> Self {
        let (proxy_url, proxy_port) = match proxy {
            Some(proxy) => (Some(proxy.proxy_url()), proxy.addr().port()),
            None => (None, 0),
        };

        Self {
            config,
            backend,
            process_tracker,
            proxy_url,
            proxy_port,
            ipc_endpoint,
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
            current_dir: None,
            stdin: StdioConfig::Inherit,
            stdout: StdioConfig::Inherit,
            stderr: StdioConfig::Inherit,
        }
    }

    /// Add a single argument
    pub fn arg(mut self, arg: impl AsRef<str>) -> Self {
        self.args.push(arg.as_ref().to_string());
        self
    }

    /// Add multiple arguments
    pub fn args(mut self, args: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_string()));
        self
    }

    /// Set an environment variable
    pub fn env(mut self, key: impl AsRef<str>, val: impl AsRef<str>) -> Self {
        self.envs
            .push((key.as_ref().to_string(), val.as_ref().to_string()));
        self
    }

    /// Set multiple environment variables
    pub fn envs(
        mut self,
        envs: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
    ) -> Self {
        self.envs.extend(
            envs.into_iter()
                .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string())),
        );
        self
    }

    /// Set the working directory
    pub fn current_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.current_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Configure stdin
    pub fn stdin(mut self, cfg: StdioConfig) -> Self {
        self.stdin = cfg;
        self
    }

    /// Configure stdout
    pub fn stdout(mut self, cfg: StdioConfig) -> Self {
        self.stdout = cfg;
        self
    }

    /// Configure stderr
    pub fn stderr(mut self, cfg: StdioConfig) -> Self {
        self.stderr = cfg;
        self
    }

    /// Build the final environment variables list, including proxy settings
    fn build_envs(&self) -> Vec<(String, String)> {
        let mut envs = self.envs.clone();

        if let Some(ref proxy_url) = self.proxy_url {
            // Auto-inject proxy environment variables
            // These ensure all network traffic goes through our proxy
            let proxy_vars = [
                ("HTTP_PROXY", proxy_url),
                ("HTTPS_PROXY", proxy_url),
                ("http_proxy", proxy_url),
                ("https_proxy", proxy_url),
            ];

            for (key, val) in proxy_vars {
                // Only add if user hasn't explicitly set it
                if !envs.iter().any(|(k, _)| k == key) {
                    envs.push((key.to_string(), val.clone()));
                }
            }
        }

        // Inject IPC endpoint and update PATH if configured
        if let Some(ref endpoint) = self.ipc_endpoint {
            if !envs.iter().any(|(k, _)| k == "HEEL_IPC_ENDPOINT") {
                envs.push(("HEEL_IPC_ENDPOINT".to_string(), endpoint.clone()));
            }

            // Add .heel/bin to PATH for IPC wrapper scripts
            let heel_bin = self.config.working_dir().join(".heel").join("bin");
            let current_path = std::env::var("PATH").unwrap_or_default();
            let new_path = format!("{}:{}", heel_bin.display(), current_path);
            // Remove any existing PATH entry and add the new one
            envs.retain(|(k, _)| k != "PATH");
            envs.push(("PATH".to_string(), new_path));
        }

        envs
    }

    /// Run the command and wait for completion, collecting all output
    pub async fn output(self) -> Result<Output> {
        let envs = self.build_envs();
        self.backend
            .execute(
                self.config,
                self.proxy_port,
                &self.program,
                &self.args,
                &envs,
                self.current_dir.as_deref(),
                StdioConfig::Null,
                StdioConfig::Piped,
                StdioConfig::Piped,
            )
            .await
    }

    /// Run the command and wait for completion, returning only the exit status
    pub async fn status(self) -> Result<ExitStatus> {
        let envs = self.build_envs();
        let output = self
            .backend
            .execute(
                self.config,
                self.proxy_port,
                &self.program,
                &self.args,
                &envs,
                self.current_dir.as_deref(),
                self.stdin,
                self.stdout,
                self.stderr,
            )
            .await?;
        Ok(output.status)
    }

    /// Spawn the command as a child process for streaming I/O
    pub async fn spawn(self) -> Result<Child> {
        let envs = self.build_envs();
        let child = self
            .backend
            .spawn(
                self.config,
                self.proxy_port,
                &self.program,
                &self.args,
                &envs,
                self.current_dir.as_deref(),
                self.stdin,
                self.stdout,
                self.stderr,
            )
            .await?;

        // Register the child process for tracking
        self.process_tracker.register(child.id());

        Ok(child.with_tracker(self.process_tracker.clone()))
    }
}
