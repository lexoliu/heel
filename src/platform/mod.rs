use std::future::Future;
use std::process::{ExitStatus, Output, Stdio};

use blocking::unblock;

use crate::config::SandboxConfigData;
use crate::error::Result;
use crate::sandbox::ProcessTracker;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// A spawned child process in the sandbox
pub struct Child {
    inner: Option<std::process::Child>,
    tracker: Option<ProcessTracker>,
    pid: u32,
}

impl Child {
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

    fn unregister_if_tracked(&mut self) {
        if let Some(tracker) = self.tracker.take() {
            tracker.unregister(self.id());
        }
    }

    /// Access the child's stdin
    pub fn stdin(&mut self) -> Option<&mut std::process::ChildStdin> {
        self.inner.as_mut().and_then(|child| child.stdin.as_mut())
    }

    /// Access the child's stdout
    pub fn stdout(&mut self) -> Option<&mut std::process::ChildStdout> {
        self.inner.as_mut().and_then(|child| child.stdout.as_mut())
    }

    /// Access the child's stderr
    pub fn stderr(&mut self) -> Option<&mut std::process::ChildStderr> {
        self.inner.as_mut().and_then(|child| child.stderr.as_mut())
    }

    /// Take ownership of the child's stdin
    pub fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.inner.as_mut().and_then(|child| child.stdin.take())
    }

    /// Take ownership of the child's stdout
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.inner.as_mut().and_then(|child| child.stdout.take())
    }

    /// Take ownership of the child's stderr
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.inner.as_mut().and_then(|child| child.stderr.take())
    }

    /// Get the process ID
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Wait for the child to exit
    pub async fn wait(&mut self) -> Result<ExitStatus> {
        let pid = self.pid;
        let tracker = self.tracker.take();
        let mut inner = self
            .inner
            .take()
            .expect("child process no longer available");
        let (inner, status) = unblock(move || {
            let status = inner.wait();
            (inner, status)
        })
        .await;
        self.inner = Some(inner);
        if let Some(tracker) = tracker {
            tracker.unregister(pid);
        }
        Ok(status?)
    }

    /// Wait for the child to exit and collect all output
    pub async fn wait_with_output(self) -> Result<Output> {
        let inner = self.inner.expect("child process no longer available");
        let pid = inner.id();
        let tracker = self.tracker;
        let output = unblock(move || inner.wait_with_output()).await?;
        if let Some(tracker) = tracker {
            tracker.unregister(pid);
        }
        Ok(output)
    }

    /// Attempt to kill the child process
    pub fn kill(&mut self) -> Result<()> {
        #[cfg(unix)]
        {
            let result = unsafe { libc::kill(-(self.pid as i32), libc::SIGKILL) };
            if result == 0 {
                return Ok(());
            }
            Err(std::io::Error::last_os_error().into())
        }

        #[cfg(not(unix))]
        {
            let inner = self
                .inner
                .as_mut()
                .expect("child process no longer available");
            Ok(inner.kill()?)
        }
    }

    /// Check if the child has exited without blocking
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        let inner = self
            .inner
            .as_mut()
            .expect("child process no longer available");
        let status = inner.try_wait()?;
        if status.is_some() {
            self.unregister_if_tracked();
        }
        Ok(status)
    }
}

/// Internal trait for platform-specific sandbox backends
pub(crate) trait Backend: Sized + Send + Sync {
    /// Execute a command and wait for completion
    #[allow(clippy::too_many_arguments)]
    fn execute(
        &self,
        config: &SandboxConfigData,
        proxy_port: u16,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        current_dir: Option<&std::path::Path>,
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
    ) -> impl Future<Output = Result<Output>> + Send;

    /// Spawn a command as a child process
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        &self,
        config: &SandboxConfigData,
        proxy_port: u16,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        current_dir: Option<&std::path::Path>,
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
    ) -> impl Future<Output = Result<Child>> + Send;
}

/// Create the native backend for the current platform
#[cfg(target_os = "macos")]
pub(crate) fn create_native_backend() -> Result<macos::MacOSBackend> {
    macos::MacOSBackend::new()
}

#[cfg(target_os = "linux")]
pub(crate) fn create_native_backend() -> Result<linux::LinuxBackend> {
    linux::LinuxBackend::new()
}

#[cfg(target_os = "windows")]
pub(crate) fn create_native_backend() -> Result<windows::WindowsBackend> {
    windows::WindowsBackend::new()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(crate) fn create_native_backend() -> Result<()> {
    Err(crate::error::Error::UnsupportedPlatform)
}
