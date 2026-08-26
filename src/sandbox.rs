//! The sandbox itself: setup, command execution and teardown.

use std::path::PathBuf;
use std::process::Output;
use std::sync::{Arc, Mutex, MutexGuard};

use blocking::unblock;
use executor_core::async_executor::AsyncExecutor;
use executor_core::{DefaultExecutor, Executor, try_init_global_executor};

use crate::command::{Command, ProxyEndpoint};
use crate::config::{SandboxConfig, SandboxConfigData};
use crate::error::{Error, Result};
use crate::ipc::{IpcLayout, IpcServer};
use crate::network::{DenyAll, NetworkPolicy, NetworkProxy};
use crate::platform::{self, NativeBackend};
use crate::workdir::WorkingDir;

/// Locate the `heel` binary that IPC wrappers execute.
///
/// Resolution is explicit and never builds anything: the configured path, then
/// `HEEL_BIN`, then this process if it is itself `heel`, then `PATH`.
fn resolve_heel_binary(configured: Option<&std::path::Path>) -> Result<PathBuf> {
    if let Some(path) = configured {
        if !path.is_file() {
            return Err(Error::InitFailed(format!(
                "the configured heel binary is missing: {}",
                path.display()
            )));
        }
        return Ok(path.to_path_buf());
    }

    if let Some(path) = std::env::var_os("HEEL_BIN") {
        let path = PathBuf::from(path);
        if !path.is_file() {
            return Err(Error::InitFailed(format!(
                "HEEL_BIN points to a missing file: {}",
                path.display()
            )));
        }
        return Ok(path);
    }

    let binary_name = format!("heel{}", std::env::consts::EXE_SUFFIX);

    // A sandbox created by the CLI can reuse the running binary directly.
    if let Ok(current) = std::env::current_exe()
        && current
            .file_name()
            .is_some_and(|name| name == binary_name.as_str())
    {
        return Ok(current);
    }

    search_path_for_binary(&binary_name).ok_or_else(|| {
        Error::InitFailed(format!(
            "cannot find the '{binary_name}' binary, which sandboxed IPC commands execute; \
             install it with `cargo install heel` or point HEEL_BIN at it"
        ))
    })
}

/// Find an executable by name on `PATH`.
fn search_path_for_binary(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Tracks the processes spawned inside a sandbox so they can be killed on drop.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProcessTracker {
    pids: Arc<Mutex<Vec<u32>>>,
}

impl ProcessTracker {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Take the lock, recovering from poisoning.
    ///
    /// A panic elsewhere must not turn cleanup into a silent no-op: leaving
    /// sandboxed processes alive is worse than reading a list that a panicking
    /// thread may have left mid-update, which for a `Vec<u32>` is still a valid
    /// list of PIDs.
    fn lock(&self) -> MutexGuard<'_, Vec<u32>> {
        self.pids.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("process tracker lock was poisoned; recovering");
            poisoned.into_inner()
        })
    }

    /// Register a spawned process.
    pub(crate) fn register(&self, pid: u32) {
        self.lock().push(pid);
        tracing::debug!(pid, "registered child process");
    }

    /// Forget a process that has already been reaped.
    pub(crate) fn unregister(&self, pid: u32) {
        self.lock().retain(|&tracked| tracked != pid);
        tracing::debug!(pid, "unregistered child process");
    }

    /// Kill every tracked process group.
    pub(crate) fn kill_all(&self) {
        let pids = std::mem::take(&mut *self.lock());

        for pid in pids {
            tracing::debug!(pid, "killing child process");

            #[cfg(unix)]
            {
                // Only signal PIDs that are still our unreaped children, so a
                // recycled PID belonging to an unrelated process is never hit.
                let mut status: libc::c_int = 0;
                // SAFETY: `status` is a valid destination and the call only
                // inspects a process this sandbox spawned.
                let waited = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
                if waited == pid as i32 {
                    tracing::debug!(pid, "child already exited");
                    continue;
                }
                if waited == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                {
                    tracing::debug!(pid, "skipping non-child PID");
                    continue;
                }

                // SAFETY: a negative PID signals the process group created at
                // spawn; the `waitpid` above established that it is still ours.
                unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
                // SAFETY: reaps the process just signalled, so the killed child
                // does not linger as a zombie.
                unsafe { libc::waitpid(pid as i32, &mut status, 0) };
            }

            #[cfg(windows)]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/T", "/PID", &pid.to_string()])
                    .output();
            }
        }
    }
}

/// A sandbox for running untrusted code with restricted permissions.
///
/// The type parameter is the network policy. With the default [`DenyAll`] no
/// proxy is started at all and the platform backend denies outbound traffic in
/// the kernel; any other policy starts a local proxy that every connection must
/// pass through.
///
/// When dropped, a sandbox stops its proxy and IPC server, kills the processes
/// it spawned, and removes its working directory unless the directory was
/// supplied by the caller or [`Sandbox::keep_working_dir`] was called.
pub struct Sandbox<N: NetworkPolicy = DenyAll> {
    config_data: SandboxConfigData,
    backend: NativeBackend,
    proxy: Option<NetworkProxy<N>>,
    ipc_server: Option<IpcServer>,
    process_tracker: ProcessTracker,
    /// Declared after the server so it is dropped later: removing the directory
    /// first would pull the socket out from under a server still shutting down.
    #[expect(
        dead_code,
        reason = "held for its Drop implementation, which removes the socket directory"
    )]
    ipc_socket_dir: Option<WorkingDir>,
    working_dir: WorkingDir,
}

impl Sandbox<DenyAll> {
    /// Create a sandbox with default configuration and no network access.
    pub async fn new() -> Result<Self> {
        let _ = try_init_global_executor(AsyncExecutor::new());
        Self::with_config_and_executor(SandboxConfig::new(), DefaultExecutor).await
    }

    /// Create a default sandbox on a specific executor.
    pub async fn with_executor<E: Executor + Clone + 'static>(executor: E) -> Result<Self> {
        Self::with_config_and_executor(SandboxConfig::new(), executor).await
    }
}

impl<N: NetworkPolicy> Sandbox<N> {
    /// Create a sandbox from a configuration.
    pub async fn with_config(config: SandboxConfig<N>) -> Result<Self> {
        let _ = try_init_global_executor(AsyncExecutor::new());
        Self::with_config_and_executor(config, DefaultExecutor).await
    }

    /// Create a sandbox from a configuration, on a specific executor.
    pub async fn with_config_and_executor<E: Executor + Clone + 'static>(
        config: SandboxConfig<N>,
        executor: E,
    ) -> Result<Self> {
        let backend = platform::create_native_backend()?;
        let (policy, mut config_data, router) = config.into_parts();

        // Create and canonicalize the working directory before anything else
        // derives paths from it.
        let requested_dir = config_data.working_dir().to_path_buf();
        let auto = config_data.working_dir_is_auto();
        let working_dir = unblock(move || WorkingDir::create(&requested_dir, auto)).await?;
        config_data.set_working_dir(working_dir.path().to_path_buf());

        // DenyAll needs no proxy: the backend denies outbound traffic outright,
        // which is a stronger guarantee than a userspace rejection.
        let proxy = if N::DENIES_ALL {
            None
        } else {
            Some(NetworkProxy::new(policy, executor.clone()).await?)
        };

        let (ipc_server, ipc_socket_dir) = match router {
            Some(router) => {
                let (server, socket_dir) =
                    Self::start_ipc(&mut config_data, working_dir.path(), router, executor).await?;
                (Some(server), Some(socket_dir))
            }
            None => (None, None),
        };

        match &proxy {
            Some(proxy) => tracing::info!(
                proxy = %proxy.addr(),
                working_dir = %working_dir.path().display(),
                "sandbox created"
            ),
            None => tracing::info!(
                working_dir = %working_dir.path().display(),
                "sandbox created (network denied)"
            ),
        }

        Ok(Self {
            config_data,
            backend,
            proxy,
            ipc_server,
            process_tracker: ProcessTracker::new(),
            ipc_socket_dir,
            working_dir,
        })
    }

    /// Write the IPC command shims and start the IPC server.
    ///
    /// Returns the server together with the private directory holding its
    /// socket, which the sandbox owns and removes on drop.
    async fn start_ipc<E: Executor + Clone + 'static>(
        config_data: &mut SandboxConfigData,
        working_dir: &std::path::Path,
        router: crate::ipc::IpcRouter,
        executor: E,
    ) -> Result<(IpcServer, WorkingDir)> {
        let layout = IpcLayout::new(working_dir);
        let heel_binary = resolve_heel_binary(config_data.heel_binary())?;

        // Writing the shims and creating the socket directory are both blocking
        // filesystem work; the router is handed to the worker and handed back so
        // it can move on to the server.
        let write_binary = heel_binary.clone();
        let (router, socket_dir) =
            unblock(move || -> Result<(crate::ipc::IpcRouter, WorkingDir)> {
                layout.write(&router, &write_binary)?;
                let socket_dir = WorkingDir::create(
                    &crate::ipc::socket_root().join(crate::workdir::generate_socket_dir_name()),
                    true,
                )?;
                Ok((router, socket_dir))
            })
            .await?;

        let socket = socket_dir.path().join(crate::ipc::SOCKET_NAME);

        // The launcher execs the host binary, so it must be executable from
        // inside the sandbox even if it lives under a restricted path.
        config_data.push_executable_path(heel_binary);
        config_data.set_ipc_socket(Some(socket.clone()));

        let server = IpcServer::new(socket, router, executor).await?;
        Ok((server, socket_dir))
    }

    /// Keep the working directory after the sandbox is dropped.
    ///
    /// Child processes are still killed on drop, regardless of this setting.
    pub fn keep_working_dir(&mut self) -> &mut Self {
        self.working_dir.keep();
        self
    }

    /// The proxy URL for `HTTP_PROXY`/`HTTPS_PROXY`, when network access is on.
    ///
    /// Returns `None` under a deny-all policy, where there is no proxy to point
    /// at rather than an empty address.
    pub fn proxy_url(&self) -> Option<String> {
        self.proxy.as_ref().map(NetworkProxy::proxy_url)
    }

    /// The IPC socket path, when IPC is configured.
    pub fn ipc_endpoint(&self) -> Option<&std::path::Path> {
        self.ipc_server.as_ref().map(IpcServer::socket_path)
    }

    /// Build a command to run in the sandbox.
    pub fn command(&self, program: impl Into<String>) -> Command<'_> {
        Command::new(
            &self.config_data,
            &self.backend,
            &self.process_tracker,
            self.proxy.as_ref().map(|proxy| ProxyEndpoint {
                url: proxy.proxy_url(),
                port: proxy.addr().port(),
            }),
            program,
        )
    }

    /// Run a Python script in the sandbox.
    ///
    /// Uses the configured virtual environment's interpreter when there is one,
    /// and the system interpreter otherwise.
    pub async fn run_python(&self, script: &str) -> Result<Output> {
        let python = match self.config_data.python() {
            Some(python) => crate::python::venv_interpreter(python.venv().path()),
            None => crate::python::system_interpreter().ok_or(Error::PythonNotFound)?,
        };

        self.command(python.to_string_lossy().to_string())
            .arg("-c")
            .arg(script)
            .output()
            .await
    }

    /// The policy-independent configuration this sandbox is running with.
    pub fn config(&self) -> &SandboxConfigData {
        &self.config_data
    }

    /// The sandbox working directory.
    pub fn working_dir(&self) -> &std::path::Path {
        self.working_dir.path()
    }

    /// Run an interactive command on a pseudo-terminal.
    ///
    /// Interactive sessions need a real terminal for line editing and job
    /// control, which a piped [`Command`] cannot provide.
    #[cfg(target_os = "macos")]
    pub fn run_interactive(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
    ) -> Result<std::process::ExitStatus> {
        crate::pty::run_with_pty(crate::pty::PtySession {
            config: &self.config_data,
            proxy_port: self.proxy.as_ref().map(|proxy| proxy.addr().port()),
            proxy_url: self.proxy.as_ref().map(NetworkProxy::proxy_url),
            tracker: &self.process_tracker,
            program,
            args,
            envs,
            current_dir: None,
        })
    }
}

impl<N: NetworkPolicy> Drop for Sandbox<N> {
    fn drop(&mut self) {
        if let Some(server) = self.ipc_server.take() {
            server.stop();
            drop(server);
            tracing::debug!("stopped IPC server");
        }

        if let Some(proxy) = &self.proxy {
            proxy.stop();
            tracing::debug!("stopped network proxy");
        }

        self.process_tracker.kill_all();
        tracing::debug!("killed sandbox child processes");

        // `working_dir` is dropped after this, removing the directory.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn working_directory_is_removed_on_drop() {
        smol::block_on(async {
            let sandbox = Sandbox::new().await.unwrap();
            let working_dir = sandbox.working_dir().to_path_buf();
            assert!(working_dir.exists());
            drop(sandbox);
            assert!(!working_dir.exists());
        });
    }

    #[test]
    fn keep_working_dir_preserves_the_directory() {
        smol::block_on(async {
            let working_dir = {
                let mut sandbox = Sandbox::new().await.unwrap();
                sandbox.keep_working_dir();
                sandbox.working_dir().to_path_buf()
            };
            assert!(working_dir.exists());
            std::fs::remove_dir_all(&working_dir).ok();
        });
    }

    #[test]
    fn deny_all_sandbox_starts_no_proxy() {
        smol::block_on(async {
            let sandbox = Sandbox::new().await.unwrap();
            assert_eq!(sandbox.proxy_url(), None);
        });
    }

    #[test]
    fn commands_run_inside_the_sandbox() {
        smol::block_on(async {
            let sandbox = Sandbox::new().await.unwrap();
            let output = sandbox
                .command("/bin/sh")
                .arg("-c")
                .arg("pwd")
                .output()
                .await
                .unwrap();

            assert!(output.status.success(), "unexpected output: {output:?}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(stdout.trim(), sandbox.working_dir().to_string_lossy());
        });
    }

    #[test]
    fn tmpdir_points_at_the_working_directory() {
        smol::block_on(async {
            let sandbox = Sandbox::new().await.unwrap();
            let output = sandbox
                .command("/bin/sh")
                .arg("-c")
                .arg("printf %s \"$TMPDIR\"")
                .output()
                .await
                .unwrap();

            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                sandbox.working_dir().to_string_lossy()
            );
        });
    }
}
