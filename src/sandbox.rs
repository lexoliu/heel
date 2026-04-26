use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::process::Output;
use std::sync::{Arc, Mutex};

use blocking::unblock;
use executor_core::async_executor::AsyncExecutor;
use executor_core::{DefaultExecutor, Executor, try_init_global_executor};

use crate::command::Command;
use crate::config::{SandboxConfig, SandboxConfigData};
use crate::error::{Error, Result};
use crate::ipc::IpcServer;
use crate::network::{DenyAll, NetworkPolicy, NetworkProxy};
use crate::platform;

use askama::Template;

/// Template for simple IPC wrapper (just forwards args)
#[derive(Template)]
#[template(path = "ipc/wrapper_simple.sh", escape = "none")]
struct SimpleWrapperTemplate<'a> {
    command: &'a str,
}

#[derive(Clone)]
struct PositionalWrapperArg {
    name: String,
    shell_var: String,
    shell_ref: String,
}

/// Template for IPC wrapper with positional argument support
#[derive(Template)]
#[template(path = "ipc/wrapper_positional.sh", escape = "none")]
struct PositionalWrapperTemplate<'a> {
    command: &'a str,
    positional_args: &'a [PositionalWrapperArg],
}

/// Template for IPC wrapper with stdin piping support
#[derive(Template)]
#[template(path = "ipc/wrapper_stdin.sh", escape = "none")]
struct StdinWrapperTemplate<'a> {
    command: &'a str,
    primary_arg: &'a str,
    stdin_arg: &'a str,
}

/// Template for the `heel` launcher placed inside `.heel/bin`.
#[derive(Template)]
#[template(path = "ipc/heel_launcher.sh", escape = "none")]
struct HeelLauncherTemplate<'a> {
    binary: &'a str,
}

/// Create a wrapper script for an IPC command.
///
/// The wrapper script calls `heel ipc <command> -- "$@"` to forward arguments
/// to the IPC handler running on the host.
///
/// If `positional_args` is provided, positional arguments are converted to named args:
/// - `["query"]` → `command "foo"` becomes `command --query "foo"`
/// - `["subagent", "prompt"]` → `command a "b"` becomes `command --subagent a --prompt "b"`
///
/// If `stdin_arg` is provided, stdin content is captured and passed as that argument.
fn create_ipc_wrapper(
    bin_dir: &Path,
    command: &str,
    positional_args: &[String],
    stdin_arg: Option<&str>,
) -> Result<()> {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let script_path = bin_dir.join(command);

    let script_content = match (positional_args.len(), stdin_arg) {
        (_, Some(stdin)) if !positional_args.is_empty() => {
            // Stdin + positional args - use template with first positional arg
            StdinWrapperTemplate {
                command,
                primary_arg: &positional_args[0],
                stdin_arg: stdin,
            }
            .render()
            .map_err(|e| Error::IoError(format!("template render failed: {e}")))?
        }
        (0, _) => {
            // No positional args - simple passthrough
            SimpleWrapperTemplate { command }
                .render()
                .map_err(|e| Error::IoError(format!("template render failed: {e}")))?
        }
        _ => {
            // Positional args without stdin - render static template
            let positional_args: Vec<PositionalWrapperArg> = positional_args
                .iter()
                .enumerate()
                .map(|(index, name)| PositionalWrapperArg {
                    name: name.clone(),
                    shell_var: format!("arg{index}"),
                    shell_ref: format!("$arg{index}"),
                })
                .collect();
            PositionalWrapperTemplate {
                command,
                positional_args: &positional_args,
            }
            .render()
            .map_err(|e| Error::IoError(format!("template render failed: {e}")))?
        }
    };

    fs::write(&script_path, script_content).map_err(|e| {
        Error::IoError(format!(
            "failed to create IPC wrapper {}: {}",
            script_path.display(),
            e
        ))
    })?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&script_path)
            .map_err(|e| Error::IoError(format!("failed to get permissions: {}", e)))?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&script_path, perms)
            .map_err(|e| Error::IoError(format!("failed to set permissions: {}", e)))?;
    }

    Ok(())
}

fn search_path_for_binary(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn bundled_heel_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    let mut binary_name = String::from("heel");
    binary_name.push_str(std::env::consts::EXE_SUFFIX);
    path.push(binary_name);
    path
}

fn path_modified_time(path: &Path) -> Result<std::time::SystemTime> {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map_err(|error| {
            Error::InitFailed(format!(
                "failed to read modification time for {}: {error}",
                path.display()
            ))
        })
}

fn newest_modified_time(path: &Path) -> Result<std::time::SystemTime> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        Error::InitFailed(format!(
            "failed to read metadata for {}: {error}",
            path.display()
        ))
    })?;
    let mut newest = metadata.modified().map_err(|error| {
        Error::InitFailed(format!(
            "failed to read modification time for {}: {error}",
            path.display()
        ))
    })?;

    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).map_err(|error| {
            Error::InitFailed(format!(
                "failed to read directory {}: {error}",
                path.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                Error::InitFailed(format!(
                    "failed to read directory entry in {}: {error}",
                    path.display()
                ))
            })?;
            let child_modified = newest_modified_time(&entry.path())?;
            if child_modified > newest {
                newest = child_modified;
            }
        }
    }

    Ok(newest)
}

fn bundled_heel_is_fresh(binary: &Path) -> Result<bool> {
    if !binary.is_file() {
        return Ok(false);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary_modified = path_modified_time(binary)?;
    let dependency_paths = [
        manifest_dir.join("Cargo.toml"),
        manifest_dir.join("Cargo.lock"),
        manifest_dir.join("src"),
        manifest_dir.join("templates"),
        manifest_dir.join("cli").join("Cargo.toml"),
        manifest_dir.join("cli").join("src"),
    ];

    for path in dependency_paths {
        if newest_modified_time(&path)? > binary_modified {
            return Ok(false);
        }
    }

    Ok(true)
}

fn ensure_bundled_heel_binary() -> Result<PathBuf> {
    let bundled = bundled_heel_path();
    if bundled_heel_is_fresh(&bundled)? {
        return Ok(bundled);
    }

    let cargo = std::env::var_os("CARGO")
        .map(PathBuf::from)
        .or_else(|| search_path_for_binary("cargo"))
        .ok_or_else(|| {
            Error::InitFailed("failed to resolve cargo while preparing heel".to_string())
        })?;

    let status = ProcessCommand::new(&cargo)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg("--bin")
        .arg("heel")
        .status()
        .map_err(|error| {
            Error::InitFailed(format!(
                "failed to start cargo build for heel using '{}': {error}",
                cargo.display()
            ))
        })?;

    if !status.success() {
        return Err(Error::InitFailed(format!(
            "cargo build --bin heel exited with status {status}"
        )));
    }

    if bundled.is_file() {
        Ok(bundled)
    } else {
        Err(Error::InitFailed(format!(
            "cargo reported success but heel binary is missing at {}",
            bundled.display()
        )))
    }
}

fn resolve_heel_binary() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("HEEL_BIN") {
        let resolved = PathBuf::from(path);
        if resolved.is_file() {
            return Ok(resolved);
        }
        return Err(Error::InitFailed(format!(
            "HEEL_BIN points to a missing file: {}",
            resolved.display()
        )));
    }

    if let Ok(bundled) = ensure_bundled_heel_binary() {
        return Ok(bundled);
    }

    search_path_for_binary(&format!("heel{}", std::env::consts::EXE_SUFFIX))
        .ok_or_else(|| Error::InitFailed("failed to resolve heel binary".to_string()))
}

fn create_heel_launcher(bin_dir: &Path, binary: &Path) -> Result<()> {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let launcher_path = bin_dir.join("heel");
    let escaped = shell_escape::unix::escape(binary.to_string_lossy());
    let launcher = HeelLauncherTemplate { binary: &escaped }
        .render()
        .map_err(|error| Error::IoError(format!("template render failed: {error}")))?;

    fs::write(&launcher_path, launcher).map_err(|error| {
        Error::IoError(format!(
            "failed to create IPC launcher {}: {}",
            launcher_path.display(),
            error
        ))
    })?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&launcher_path)
            .map_err(|error| Error::IoError(format!("failed to get permissions: {error}")))?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&launcher_path, perms)
            .map_err(|error| Error::IoError(format!("failed to set permissions: {error}")))?;
    }

    Ok(())
}

#[cfg(target_os = "macos")]
type NativeBackend = platform::macos::MacOSBackend;

#[cfg(target_os = "linux")]
type NativeBackend = platform::linux::LinuxBackend;

#[cfg(target_os = "windows")]
type NativeBackend = platform::windows::WindowsBackend;

/// Tracks child processes spawned within the sandbox
#[derive(Debug, Clone, Default)]
pub(crate) struct ProcessTracker {
    pids: Arc<Mutex<Vec<u32>>>,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self {
            pids: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a new child process
    pub fn register(&self, pid: u32) {
        if let Ok(mut pids) = self.pids.lock() {
            pids.push(pid);
            tracing::debug!(pid = pid, "registered child process");
        }
    }

    /// Unregister a process (when it exits normally)
    pub fn unregister(&self, pid: u32) {
        if let Ok(mut pids) = self.pids.lock() {
            pids.retain(|&p| p != pid);
            tracing::debug!(pid = pid, "unregistered child process");
        }
    }

    /// Kill all tracked processes
    pub fn kill_all(&self) {
        if let Ok(mut pids) = self.pids.lock() {
            for &pid in pids.iter() {
                tracing::debug!(pid = pid, "killing child process");
                #[cfg(unix)]
                {
                    // Avoid signaling unrelated reused PIDs: only kill if the PID
                    // is still one of our unreaped child processes.
                    let mut status: libc::c_int = 0;
                    let wait_result =
                        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
                    if wait_result == pid as i32 {
                        tracing::debug!(pid = pid, "child already exited");
                        continue;
                    }
                    if wait_result == -1 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::ECHILD) {
                            tracing::debug!(pid = pid, "skipping non-child PID");
                            continue;
                        }
                    }

                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                }
                #[cfg(windows)]
                {
                    kill_windows_process_tree(pid);
                }
            }
            pids.clear();
        }
    }
}

#[cfg(windows)]
fn kill_windows_process_tree(pid: u32) {
    let Some(command) = windows_taskkill_process_tree_command_from_env(pid, std::env::vars_os())
    else {
        tracing::warn!(
            pid = pid,
            "failed to resolve System32 taskkill.exe from SystemRoot or WINDIR"
        );
        return;
    };

    match ProcessCommand::new(&command.executable)
        .args(&command.args)
        .output()
    {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                pid = pid,
                executable = %command.executable.display(),
                status = %output.status,
                stderr = %stderr.trim(),
                "taskkill process-tree cleanup failed"
            );
        }
        Err(error) => {
            tracing::warn!(
                pid = pid,
                executable = %command.executable.display(),
                "failed to spawn taskkill process-tree cleanup: {error}"
            );
        }
    }
}

#[cfg(any(test, windows))]
fn windows_taskkill_process_tree_args(pid: u32) -> [String; 4] {
    [
        "/F".to_string(),
        "/T".to_string(),
        "/PID".to_string(),
        pid.to_string(),
    ]
}

#[cfg(any(test, windows))]
#[derive(Debug, PartialEq, Eq)]
struct WindowsTaskkillCommand {
    executable: PathBuf,
    args: [String; 4],
}

#[cfg(any(test, windows))]
fn windows_taskkill_process_tree_command_from_env(
    pid: u32,
    env: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Option<WindowsTaskkillCommand> {
    let mut system_root = None;
    let mut windir = None;

    for (key, value) in env {
        if value.as_os_str().is_empty() {
            continue;
        }

        let key = key.to_string_lossy();
        if key.eq_ignore_ascii_case("SystemRoot") && system_root.is_none() {
            system_root = Some(PathBuf::from(value));
        } else if key.eq_ignore_ascii_case("WINDIR") && windir.is_none() {
            windir = Some(PathBuf::from(value));
        }
    }

    let windows_root = system_root.or(windir)?;
    Some(WindowsTaskkillCommand {
        executable: windows_root.join("System32").join("taskkill.exe"),
        args: windows_taskkill_process_tree_args(pid),
    })
}

/// A sandbox for running untrusted code with restricted permissions
///
/// All network traffic from sandboxed processes is routed through a local proxy
/// that applies the configured NetworkPolicy for filtering and logging.
///
/// When dropped, the sandbox will:
/// - Stop the network proxy
/// - Stop the IPC server (if enabled)
/// - Kill all child processes that were spawned within it
/// - Delete the working directory if it was auto-created,
///   unless `keep_working_dir()` was called
pub struct Sandbox<N: NetworkPolicy = DenyAll> {
    config_data: SandboxConfigData,
    backend: NativeBackend,
    proxy: Option<NetworkProxy<N>>,
    ipc_server: Option<IpcServer>,
    process_tracker: ProcessTracker,
    working_dir_path: PathBuf,
    working_dir_auto_created: bool,
    keep_working_dir: bool,
}

impl Sandbox<DenyAll> {
    /// Create a new sandbox with default configuration
    ///
    /// Uses the global executor from executor-core (initialized with AsyncExecutor if not set).
    /// Creates a random working directory in the current directory
    /// using four English words connected by hyphens.
    ///
    /// By default, all network access is denied (DenyAll policy).
    pub async fn new() -> Result<Self> {
        let _ = try_init_global_executor(AsyncExecutor::new());
        Self::with_config_and_executor(SandboxConfig::new()?, DefaultExecutor).await
    }

    /// Create a new sandbox with a custom executor
    ///
    /// Use this when you want to integrate with a specific async runtime
    /// (e.g., tokio, async-std) instead of the default executor.
    pub async fn with_executor<E: Executor + Clone + 'static>(executor: E) -> Result<Self> {
        Self::with_config_and_executor(SandboxConfig::new()?, executor).await
    }
}

impl<N: NetworkPolicy + 'static> Sandbox<N> {
    /// Create a sandbox with custom configuration
    ///
    /// Uses the global executor from executor-core (initialized with AsyncExecutor if not set).
    pub async fn with_config(config: SandboxConfig<N>) -> Result<Self> {
        let _ = try_init_global_executor(AsyncExecutor::new());
        Self::with_config_and_executor(config, DefaultExecutor).await
    }

    /// Create a sandbox with custom configuration and executor
    ///
    /// Use this when you want full control over both the configuration
    /// and the async runtime executor.
    pub async fn with_config_and_executor<E: Executor + Clone + 'static>(
        config: SandboxConfig<N>,
        executor: E,
    ) -> Result<Self> {
        let backend = platform::create_native_backend()?;

        // Extract the network policy for the proxy
        let (policy, mut config_data) = config.into_parts();
        let working_dir_path = config_data.working_dir.clone();
        let working_dir_auto_created = config_data.working_dir_auto_created;

        // Create and start the network proxy (skip for DenyAll)
        let proxy = if config_data.network_deny_all() {
            None
        } else {
            Some(NetworkProxy::new(policy, executor.clone()).await?)
        };

        // Start IPC server if configured
        let ipc_server = if let Some(router) = config_data.ipc.take() {
            let heel_dir = working_dir_path.join(".heel");
            let heel_binary = resolve_heel_binary()?;
            let heel_binary_for_launcher = heel_binary.clone();

            // Create wrapper scripts for each IPC command
            let bin_dir = heel_dir.join("bin");
            let bin_dir_for_log = bin_dir.clone();
            let method_metadata: Vec<(String, Vec<String>, Option<String>)> = router
                .methods()
                .map(|(method, meta)| {
                    (
                        method.to_string(),
                        meta.positional_args.clone(),
                        meta.stdin_arg.clone(),
                    )
                })
                .collect();
            unblock(move || -> crate::error::Result<()> {
                std::fs::create_dir_all(&bin_dir)?;
                create_heel_launcher(&bin_dir, &heel_binary_for_launcher)?;
                for (method, positional_args, stdin_arg) in method_metadata {
                    create_ipc_wrapper(&bin_dir, &method, &positional_args, stdin_arg.as_deref())?;
                }
                Ok(())
            })
            .await?;
            if !config_data
                .executable_paths
                .iter()
                .any(|path| path == &heel_binary)
            {
                config_data.executable_paths.push(heel_binary.clone());
            }
            tracing::debug!(bin_dir = %bin_dir_for_log.display(), "created IPC wrapper scripts");

            let server = IpcServer::new(router, executor).await?;
            config_data.set_ipc_port(Some(server.addr().port()));
            tracing::info!(endpoint = %server.endpoint(), "IPC server started");
            Some(server)
        } else {
            None
        };

        if let Some(ref proxy) = proxy {
            tracing::info!(
                proxy_addr = %proxy.addr(),
                working_dir = %working_dir_path.display(),
                "sandbox created"
            );
        } else {
            tracing::info!(
                working_dir = %working_dir_path.display(),
                "sandbox created (network disabled)"
            );
        }

        Ok(Self {
            config_data,
            backend,
            proxy,
            ipc_server,
            process_tracker: ProcessTracker::new(),
            working_dir_path,
            working_dir_auto_created,
            keep_working_dir: false,
        })
    }

    /// Keep the working directory after the sandbox is dropped
    ///
    /// By default, auto-created working directories are deleted when the sandbox is dropped.
    /// User-provided working directories are preserved by default.
    /// Call this method to preserve the working directory for inspection or reuse.
    ///
    /// Note: Child processes are always killed when the sandbox is dropped,
    /// regardless of this setting.
    pub fn keep_working_dir(&mut self) -> &mut Self {
        self.keep_working_dir = true;
        self
    }

    /// Get the proxy URL for environment variables
    ///
    /// This URL should be set as HTTP_PROXY and HTTPS_PROXY for processes
    /// that need network access through the sandbox's proxy.
    pub fn proxy_url(&self) -> String {
        self.proxy
            .as_ref()
            .map(|proxy| proxy.proxy_url())
            .unwrap_or_default()
    }

    /// Create a command builder for running a program in the sandbox
    ///
    /// The command will automatically have HTTP_PROXY and HTTPS_PROXY
    /// environment variables set to route traffic through the sandbox's proxy.
    /// If IPC is configured, HEEL_IPC_ENDPOINT will also be set.
    pub fn command(&self, program: impl Into<String>) -> Command<'_> {
        let ipc_endpoint = self.ipc_server.as_ref().map(|s| s.endpoint().to_string());
        Command::new(
            &self.config_data,
            &self.backend,
            &self.process_tracker,
            self.proxy.as_ref(),
            ipc_endpoint,
            program,
        )
    }

    /// Run a Python script in the sandbox
    ///
    /// The script will be executed using the Python interpreter from the configured
    /// virtual environment, or the system Python if no venv is configured.
    pub async fn run_python(&self, script: &str) -> Result<Output> {
        // Determine the Python interpreter to use
        let python = if let Some(python_config) = self.config_data.python() {
            // Use venv Python if configured
            let venv_path = python_config.venv().path();
            if cfg!(windows) {
                venv_path.join("Scripts").join("python.exe")
            } else {
                venv_path.join("bin").join("python")
            }
        } else {
            // Use system Python
            resolve_python_interpreter().ok_or(crate::error::Error::PythonNotFound)?
        };

        self.command(python.to_string_lossy().to_string())
            .arg("-c")
            .arg(script)
            .output()
            .await
    }

    /// Get a reference to the sandbox configuration data
    pub fn config(&self) -> &SandboxConfigData {
        &self.config_data
    }

    /// Get the path to the working directory
    pub fn working_dir(&self) -> &std::path::Path {
        &self.working_dir_path
    }

    /// Run an interactive command with PTY support
    ///
    /// This method spawns the command with a proper pseudo-terminal, enabling
    /// interactive shell sessions with line editing, job control, and proper
    /// terminal handling. Use this for `heel shell` or any interactive command.
    ///
    /// # Arguments
    /// * `program` - The program to run
    /// * `args` - Arguments to pass to the program
    /// * `envs` - Additional environment variables to set
    ///
    /// # Returns
    /// The exit status of the command
    #[cfg(target_os = "macos")]
    pub fn run_interactive(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
    ) -> Result<crate::pty::PtyExitStatus> {
        let ipc_endpoint = self.ipc_server.as_ref().map(|s| s.endpoint());
        crate::pty::run_with_pty(
            &self.config_data,
            self.proxy.as_ref(),
            ipc_endpoint,
            program,
            args,
            envs,
            None,
        )
    }
}

#[cfg(feature = "python")]
fn resolve_python_interpreter() -> Option<std::path::PathBuf> {
    which::which("python3")
        .ok()
        .or_else(|| which::which("python").ok())
}

#[cfg(not(feature = "python"))]
fn resolve_python_interpreter() -> Option<std::path::PathBuf> {
    None
}

impl<N: NetworkPolicy> Drop for Sandbox<N> {
    fn drop(&mut self) {
        // Stop the IPC server
        if let Some(ref ipc_server) = self.ipc_server {
            ipc_server.stop();
            tracing::debug!("stopped IPC server");
        }
        // Drop the IPC server before removing working dir
        self.ipc_server.take();

        // Stop the network proxy
        if let Some(ref proxy) = self.proxy {
            proxy.stop();
            tracing::debug!("stopped network proxy");
        }

        // Kill all child processes
        self.process_tracker.kill_all();
        tracing::debug!("killed all sandbox child processes");

        // Delete auto-created working directory unless keep_working_dir was called
        let should_delete = !self.keep_working_dir && self.working_dir_auto_created;

        if should_delete {
            if let Err(e) = remove_dir_all::remove_dir_all(&self.working_dir_path) {
                tracing::warn!(
                    path = %self.working_dir_path.display(),
                    error = %e,
                    "failed to remove working directory"
                );
            } else {
                tracing::debug!(
                    path = %self.working_dir_path.display(),
                    "removed working directory"
                );
            }
        } else {
            tracing::debug!(
                path = %self.working_dir_path.display(),
                "keeping working directory"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use crate::Sandbox;

    #[test]
    fn windows_taskkill_args_include_tree_cleanup_flag() {
        assert_eq!(
            super::windows_taskkill_process_tree_args(42),
            [
                "/F".to_string(),
                "/T".to_string(),
                "/PID".to_string(),
                "42".to_string()
            ]
        );
    }

    #[test]
    fn windows_taskkill_command_uses_system32_executable_from_systemroot() {
        let command = super::windows_taskkill_process_tree_command_from_env(
            42,
            [(
                std::ffi::OsString::from("SystemRoot"),
                std::ffi::OsString::from(r"C:\Windows"),
            )],
        )
        .expect("taskkill command");

        assert_eq!(
            command.executable,
            std::path::Path::new(r"C:\Windows")
                .join("System32")
                .join("taskkill.exe")
        );
        assert_eq!(command.args, super::windows_taskkill_process_tree_args(42));
    }

    #[test]
    fn windows_taskkill_command_requires_windows_root_environment() {
        assert!(
            super::windows_taskkill_process_tree_command_from_env(
                42,
                [(
                    std::ffi::OsString::from("PATH"),
                    std::ffi::OsString::from(r"C:\Temp"),
                )],
            )
            .is_none()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_sandbox_creation() {
        smol::block_on(async {
            let sandbox = Sandbox::new().await.unwrap();
            let working_dir = sandbox.working_dir().to_path_buf();
            assert!(working_dir.exists());
            drop(sandbox);
            // Working dir should be deleted after drop
            assert!(!working_dir.exists());
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_keep_working_dir() {
        smol::block_on(async {
            let working_dir = {
                let mut sandbox = Sandbox::new().await.unwrap();
                sandbox.keep_working_dir();
                sandbox.working_dir().to_path_buf()
            };
            // Working dir should still exist after drop
            assert!(working_dir.exists());
            // Clean up manually
            std::fs::remove_dir(&working_dir).ok();
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_sandbox_executes_bash_pwd() {
        smol::block_on(async {
            let sandbox = Sandbox::new().await.unwrap();
            let output = sandbox
                .command("bash")
                .arg("-c")
                .arg("pwd")
                .output()
                .await
                .unwrap();
            eprintln!("SANDBOX OUTPUT: {:?}", output);
            assert!(output.status.success(), "unexpected output: {:?}", output);
            assert!(!output.stdout.is_empty(), "stdout should not be empty");
        });
    }
}
