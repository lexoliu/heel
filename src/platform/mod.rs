use std::future::Future;
use std::path::Path;
use std::process::{ExitStatus, Output, Stdio};

use blocking::unblock;

use crate::config::SandboxConfigData;
use crate::error::Result;
use crate::sandbox::ProcessTracker;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

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
    pub stdin: Stdio,
    /// Standard output configuration.
    pub stdout: Stdio,
    /// Standard error configuration.
    pub stderr: Stdio,
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
impl SpawnRequest<'_> {
    /// The directory the process starts in.
    pub(crate) fn working_dir(&self) -> &Path {
        self.current_dir.unwrap_or(self.config.working_dir())
    }
}

/// A spawned child process in the sandbox.
pub struct Child {
    inner: Option<std::process::Child>,
    tracker: Option<ProcessTracker>,
    pid: u32,
}

impl Child {
    /// Wrap a freshly spawned process. Only backends call this, so it is unused
    /// on Windows, where no backend is implemented yet.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub(crate) fn new(inner: std::process::Child) -> Self {
        let pid = inner.id();
        Self {
            inner: Some(inner),
            tracker: None,
            pid,
        }
    }

    pub(crate) fn with_tracker(mut self, tracker: ProcessTracker) -> Self {
        self.tracker = Some(tracker);
        self
    }

    /// The `std` handle, which is present until the child has been waited on.
    fn handle(&mut self) -> Result<&mut std::process::Child> {
        self.inner.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "child process has already been consumed",
            )
            .into()
        })
    }

    fn unregister(&mut self) {
        if let Some(tracker) = self.tracker.take() {
            tracker.unregister(self.pid);
        }
    }

    /// Access the child's stdin.
    pub fn stdin(&mut self) -> Option<&mut std::process::ChildStdin> {
        self.inner.as_mut().and_then(|child| child.stdin.as_mut())
    }

    /// Access the child's stdout.
    pub fn stdout(&mut self) -> Option<&mut std::process::ChildStdout> {
        self.inner.as_mut().and_then(|child| child.stdout.as_mut())
    }

    /// Access the child's stderr.
    pub fn stderr(&mut self) -> Option<&mut std::process::ChildStderr> {
        self.inner.as_mut().and_then(|child| child.stderr.as_mut())
    }

    /// Take ownership of the child's stdin.
    pub fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.inner.as_mut().and_then(|child| child.stdin.take())
    }

    /// Take ownership of the child's stdout.
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.inner.as_mut().and_then(|child| child.stdout.take())
    }

    /// Take ownership of the child's stderr.
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.inner.as_mut().and_then(|child| child.stderr.take())
    }

    /// The process ID.
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Wait for the child to exit.
    pub async fn wait(&mut self) -> Result<ExitStatus> {
        let mut inner = self.inner.take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "child process has already been consumed",
            )
        })?;
        let (inner, status) = unblock(move || {
            let status = inner.wait();
            (inner, status)
        })
        .await;
        self.inner = Some(inner);
        let status = status?;
        self.unregister();
        Ok(status)
    }

    /// Wait for the child to exit and collect all output.
    pub async fn wait_with_output(mut self) -> Result<Output> {
        let inner = self.inner.take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "child process has already been consumed",
            )
        })?;
        let output = unblock(move || inner.wait_with_output()).await?;
        self.unregister();
        Ok(output)
    }

    /// Kill the child and everything it spawned, then reap it.
    ///
    /// Sandboxed processes run in their own process group, so the whole group
    /// is signalled; the child is then waited on so it does not linger as a
    /// zombie. Killing an already-exited child succeeds.
    pub fn kill(&mut self) -> Result<()> {
        #[cfg(unix)]
        {
            // SAFETY: a negative PID targets the process group created at
            // spawn, which is this child and its descendants.
            let result = unsafe { libc::kill(-(self.pid as i32), libc::SIGKILL) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                // ESRCH means the group is already gone, which is success here.
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error.into());
                }
            }
        }

        #[cfg(not(unix))]
        {
            if let Ok(handle) = self.handle() {
                handle.kill()?;
            }
        }

        // Reap so the kernel releases the entry rather than leaving a zombie.
        if let Some(handle) = self.inner.as_mut() {
            handle.wait()?;
        }
        self.unregister();
        Ok(())
    }

    /// Check whether the child has exited, without blocking.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        let status = self.handle()?.try_wait()?;
        if status.is_some() {
            self.unregister();
        }
        Ok(status)
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
