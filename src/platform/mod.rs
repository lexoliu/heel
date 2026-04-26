use std::future::Future;
#[cfg(target_os = "windows")]
use std::io::Read;
#[cfg(target_os = "windows")]
use std::os::windows::process::ExitStatusExt;
use std::process::{ExitStatus, Output};
#[cfg(target_os = "windows")]
use std::thread;

#[cfg(target_os = "windows")]
use ::windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
#[cfg(target_os = "windows")]
use ::windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
#[cfg(target_os = "windows")]
use ::windows::core::Error as WindowsError;
use blocking::unblock;

use crate::config::SandboxConfigData;
#[cfg(target_os = "windows")]
use crate::error::Error;
use crate::error::Result;
#[cfg(target_os = "windows")]
use crate::platform::windows::{AppContainerLaunchState, job::JobGuard};
use crate::sandbox::ProcessTracker;
use crate::stdio::{ChildStderr, ChildStdin, ChildStdout, StdioConfig};

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(test, target_os = "windows"))]
pub mod windows;

/// A spawned child process in the sandbox
pub struct Child {
    inner: ChildInner,
    tracker: Option<ProcessTracker>,
    pid: u32,
}

enum ChildInner {
    #[cfg(not(target_os = "windows"))]
    Std(Option<std::process::Child>),
    #[cfg(target_os = "windows")]
    Windows(Option<WindowsChild>),
}

#[cfg(target_os = "windows")]
struct WindowsChild {
    process: WindowsHandle,
    _thread: WindowsHandle,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    exit_status: Option<ExitStatus>,
    job: Option<JobGuard>,
    _launch_state: AppContainerLaunchState,
}

#[cfg(target_os = "windows")]
struct WindowsHandle {
    handle: HANDLE,
    label: &'static str,
}

#[cfg(target_os = "windows")]
unsafe impl Send for WindowsHandle {}

#[cfg(target_os = "windows")]
impl WindowsHandle {
    fn new(handle: HANDLE, label: &'static str) -> Result<Self> {
        if handle.is_invalid() {
            return Err(Error::FfiError(format!(
                "Windows {label} handle was invalid"
            )));
        }

        Ok(Self { handle, label })
    }

    fn raw_value(&self) -> usize {
        self.handle.0 as usize
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            if let Err(error) = unsafe { CloseHandle(self.handle) } {
                tracing::warn!(
                    handle = self.label,
                    "failed to close Windows handle: {error}"
                );
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl WindowsChild {
    async fn wait(&mut self) -> Result<ExitStatus> {
        if let Some(status) = self.exit_status {
            self.close_job();
            return Ok(status);
        }

        let process = self.process.raw_value();
        let status = unblock(move || wait_for_windows_process(process)).await?;
        Ok(self.record_exit_status(status))
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        if let Some(status) = self.exit_status {
            self.close_job();
            return Ok(Some(status));
        }

        let process = handle_from_raw_value(self.process.raw_value());
        match unsafe { WaitForSingleObject(process, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let status = windows_exit_status(process)?;
                Ok(Some(self.record_exit_status(status)))
            }
            WAIT_FAILED => Err(Error::FfiError(format!(
                "WaitForSingleObject failed: {}",
                WindowsError::from_win32()
            ))),
            event => Err(Error::FfiError(format!(
                "WaitForSingleObject returned unexpected event {}",
                event.0
            ))),
        }
    }

    fn kill(&mut self) -> Result<()> {
        self.terminate_job(1)
    }

    fn terminate_job(&self, exit_code: u32) -> Result<()> {
        let job = self.job.as_ref().ok_or_else(|| {
            Error::ProcessError(std::io::Error::other(
                "Windows job object is already closed",
            ))
        })?;

        job.terminate(exit_code)
    }

    fn close_job(&mut self) {
        drop(self.job.take());
    }

    fn record_exit_status(&mut self, status: ExitStatus) -> ExitStatus {
        self.exit_status = Some(status);
        self.close_job();
        status
    }

    async fn wait_with_output(mut self) -> Result<Output> {
        drop(self.stdin.take());

        let stdout = self.stdout.take().map(read_windows_pipe);
        let stderr = self.stderr.take().map(read_windows_pipe);
        let status = self.wait().await?;
        self.close_job();

        Ok(Output {
            status,
            stdout: join_windows_pipe(stdout)?,
            stderr: join_windows_pipe(stderr)?,
        })
    }
}

#[cfg(target_os = "windows")]
fn read_windows_pipe(mut pipe: std::fs::File) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut buffer = Vec::new();
        pipe.read_to_end(&mut buffer)?;
        Ok(buffer)
    })
}

#[cfg(target_os = "windows")]
fn join_windows_pipe(
    handle: Option<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
) -> Result<Vec<u8>> {
    Ok(match handle {
        Some(handle) => handle.join().map_err(|_| {
            Error::ProcessError(std::io::Error::other("pipe reader thread panicked"))
        })??,
        None => Vec::new(),
    })
}

#[cfg(target_os = "windows")]
fn wait_for_windows_process(process: usize) -> Result<ExitStatus> {
    let process = handle_from_raw_value(process);
    match unsafe { WaitForSingleObject(process, INFINITE) } {
        WAIT_OBJECT_0 => windows_exit_status(process),
        WAIT_FAILED => Err(Error::FfiError(format!(
            "WaitForSingleObject failed: {}",
            WindowsError::from_win32()
        ))),
        event => Err(Error::FfiError(format!(
            "WaitForSingleObject returned unexpected event {}",
            event.0
        ))),
    }
}

#[cfg(target_os = "windows")]
fn windows_exit_status(process: HANDLE) -> Result<ExitStatus> {
    let mut exit_code = 0;
    unsafe {
        GetExitCodeProcess(process, &mut exit_code)
            .map_err(|error| Error::FfiError(format!("GetExitCodeProcess failed: {error}")))?;
    }

    Ok(ExitStatus::from_raw(exit_code))
}

#[cfg(target_os = "windows")]
fn handle_from_raw_value(value: usize) -> HANDLE {
    HANDLE(value as *mut core::ffi::c_void)
}

impl Child {
    #[cfg(not(target_os = "windows"))]
    pub(crate) fn from_std(inner: std::process::Child) -> Self {
        let pid = inner.id();
        Self {
            inner: ChildInner::Std(Some(inner)),
            tracker: None,
            pid,
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub(crate) fn new(inner: std::process::Child) -> Self {
        Self::from_std(inner)
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn from_windows(
        process: HANDLE,
        thread: HANDLE,
        pid: u32,
        stdin: Option<ChildStdin>,
        stdout: Option<ChildStdout>,
        stderr: Option<ChildStderr>,
        job: JobGuard,
        launch_state: AppContainerLaunchState,
    ) -> Result<Self> {
        Ok(Self {
            inner: ChildInner::Windows(Some(WindowsChild {
                process: WindowsHandle::new(process, "process")?,
                _thread: WindowsHandle::new(thread, "thread")?,
                stdin,
                stdout,
                stderr,
                exit_status: None,
                job: Some(job),
                _launch_state: launch_state,
            })),
            tracker: None,
            pid,
        })
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

    #[cfg(not(target_os = "windows"))]
    fn std_child_slot(&mut self) -> &mut Option<std::process::Child> {
        match &mut self.inner {
            ChildInner::Std(inner) => inner,
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_child_slot(&mut self) -> &mut Option<WindowsChild> {
        match &mut self.inner {
            ChildInner::Windows(inner) => inner,
        }
    }

    /// Access the child's stdin
    pub fn stdin(&mut self) -> Option<&mut ChildStdin> {
        #[cfg(not(target_os = "windows"))]
        {
            self.std_child_slot()
                .as_mut()
                .and_then(|child| child.stdin.as_mut())
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_child_slot()
                .as_mut()
                .and_then(|child| child.stdin.as_mut())
        }
    }

    /// Access the child's stdout
    pub fn stdout(&mut self) -> Option<&mut ChildStdout> {
        #[cfg(not(target_os = "windows"))]
        {
            self.std_child_slot()
                .as_mut()
                .and_then(|child| child.stdout.as_mut())
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_child_slot()
                .as_mut()
                .and_then(|child| child.stdout.as_mut())
        }
    }

    /// Access the child's stderr
    pub fn stderr(&mut self) -> Option<&mut ChildStderr> {
        #[cfg(not(target_os = "windows"))]
        {
            self.std_child_slot()
                .as_mut()
                .and_then(|child| child.stderr.as_mut())
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_child_slot()
                .as_mut()
                .and_then(|child| child.stderr.as_mut())
        }
    }

    /// Take ownership of the child's stdin
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        #[cfg(not(target_os = "windows"))]
        {
            self.std_child_slot()
                .as_mut()
                .and_then(|child| child.stdin.take())
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_child_slot()
                .as_mut()
                .and_then(|child| child.stdin.take())
        }
    }

    /// Take ownership of the child's stdout
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        #[cfg(not(target_os = "windows"))]
        {
            self.std_child_slot()
                .as_mut()
                .and_then(|child| child.stdout.take())
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_child_slot()
                .as_mut()
                .and_then(|child| child.stdout.take())
        }
    }

    /// Take ownership of the child's stderr
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        #[cfg(not(target_os = "windows"))]
        {
            self.std_child_slot()
                .as_mut()
                .and_then(|child| child.stderr.take())
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_child_slot()
                .as_mut()
                .and_then(|child| child.stderr.take())
        }
    }

    /// Get the process ID
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Wait for the child to exit
    pub async fn wait(&mut self) -> Result<ExitStatus> {
        #[cfg(not(target_os = "windows"))]
        {
            let pid = self.pid;
            let tracker = self.tracker.take();
            let mut child = self
                .std_child_slot()
                .take()
                .expect("child process no longer available");
            let (child, status) = unblock(move || {
                let status = child.wait();
                (child, status)
            })
            .await;
            *self.std_child_slot() = Some(child);
            if let Some(tracker) = tracker {
                tracker.unregister(pid);
            }
            Ok(status?)
        }

        #[cfg(target_os = "windows")]
        {
            let pid = self.pid;
            let tracker = self.tracker.take();
            let child = self
                .windows_child_slot()
                .as_mut()
                .expect("child process no longer available");
            let status = child.wait().await?;
            if let Some(tracker) = tracker {
                tracker.unregister(pid);
            }
            Ok(status)
        }
    }

    /// Wait for the child to exit and collect all output
    pub async fn wait_with_output(self) -> Result<Output> {
        #[cfg(not(target_os = "windows"))]
        {
            match self.inner {
                ChildInner::Std(inner) => {
                    let child = inner.expect("child process no longer available");
                    let pid = child.id();
                    let tracker = self.tracker;
                    let output = unblock(move || child.wait_with_output()).await?;
                    if let Some(tracker) = tracker {
                        tracker.unregister(pid);
                    }
                    Ok(output)
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            let Child {
                inner,
                tracker,
                pid,
            } = self;
            let child = match inner {
                ChildInner::Windows(inner) => inner.expect("child process no longer available"),
            };
            let output = child.wait_with_output().await?;
            if let Some(tracker) = tracker {
                tracker.unregister(pid);
            }
            Ok(output)
        }
    }

    /// Attempt to kill the child process
    pub fn kill(&mut self) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            let child = self
                .std_child_slot()
                .as_mut()
                .expect("child process no longer available");
            Ok(child.kill()?)
        }

        #[cfg(target_os = "windows")]
        {
            let child = self
                .windows_child_slot()
                .as_mut()
                .expect("child process no longer available");
            child.kill()
        }
    }

    /// Check if the child has exited without blocking
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        #[cfg(not(target_os = "windows"))]
        {
            let child = self
                .std_child_slot()
                .as_mut()
                .expect("child process no longer available");
            let status = child.try_wait()?;
            if status.is_some() {
                self.unregister_if_tracked();
            }
            Ok(status)
        }

        #[cfg(target_os = "windows")]
        {
            let status = self
                .windows_child_slot()
                .as_mut()
                .expect("child process no longer available")
                .try_wait()?;
            if status.is_some() {
                self.unregister_if_tracked();
            }
            Ok(status)
        }
    }
}

/// Static sandbox capability metadata for the current target platform.
///
/// This describes which backend features this crate build implements for the
/// target OS. Runtime initialization can still fail because of OS version,
/// kernel, entitlement, or host policy requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlatformCapabilities {
    /// Diagnostic backend identifier.
    ///
    /// This string is intended for logs, telemetry, and user-facing status. Do
    /// not branch on it for capability decisions; use the typed boolean fields.
    pub backend: &'static str,
    /// Whether sandboxed command execution is ready for applications to rely on
    /// for this target.
    ///
    /// If this is false, application layers must treat the backend as
    /// unavailable for sandbox-guaranteed flows. A backend may still contain
    /// staged implementation code behind this capability while adjacent safety
    /// work, such as ACL restoration or process-tree cleanup, is still in
    /// progress.
    pub execution_supported: bool,
    /// Whether the backend supports strict filesystem root enforcement.
    pub filesystem_strict: bool,
    /// Whether the backend can enforce a deny-all network policy.
    pub network_deny_all: bool,
    /// Whether the backend can enforce network allowlists through Heel policy.
    pub network_allowlist: bool,
    /// Whether Heel IPC is supported from sandboxed children on this platform.
    pub ipc: bool,
    /// Whether child process tree cleanup is implemented by the platform backend.
    pub background_process_tree_cleanup: bool,
}

#[cfg(target_os = "macos")]
pub fn platform_capabilities() -> PlatformCapabilities {
    macos_capabilities()
}

#[cfg(any(test, target_os = "macos"))]
fn macos_capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        backend: "macos_sandbox_exec",
        execution_supported: true,
        filesystem_strict: false,
        network_deny_all: true,
        network_allowlist: true,
        ipc: true,
        background_process_tree_cleanup: false,
    }
}

#[cfg(target_os = "linux")]
pub fn platform_capabilities() -> PlatformCapabilities {
    linux_capabilities()
}

#[cfg(any(test, target_os = "linux"))]
fn linux_capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        backend: "linux_landlock_seccomp",
        execution_supported: true,
        filesystem_strict: true,
        network_deny_all: true,
        network_allowlist: true,
        ipc: true,
        background_process_tree_cleanup: false,
    }
}

#[cfg(target_os = "windows")]
pub fn platform_capabilities() -> PlatformCapabilities {
    windows_capabilities()
}

#[cfg(any(test, target_os = "windows"))]
fn windows_capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        backend: "windows_appcontainer",
        execution_supported: true,
        filesystem_strict: true,
        network_deny_all: true,
        network_allowlist: false,
        ipc: false,
        background_process_tree_cleanup: true,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn platform_capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        backend: "unsupported",
        execution_supported: false,
        filesystem_strict: false,
        network_deny_all: false,
        network_allowlist: false,
        ipc: false,
        background_process_tree_cleanup: false,
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
        stdin: StdioConfig,
        stdout: StdioConfig,
        stderr: StdioConfig,
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
        stdin: StdioConfig,
        stdout: StdioConfig,
        stderr: StdioConfig,
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

#[cfg(test)]
mod tests {
    use super::platform_capabilities;

    #[cfg(unix)]
    #[test]
    fn child_wraps_std_process_id() {
        let std_child = std::process::Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn test child");
        let expected_pid = std_child.id();

        let child = super::Child::from_std(std_child);

        assert_eq!(child.id(), expected_pid);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_handle_rejects_invalid_process_handle() {
        use windows::Win32::Foundation::HANDLE;

        let result = super::WindowsHandle::new(HANDLE::default(), "process");

        match result {
            Ok(_) => panic!("invalid process handle should be rejected"),
            Err(err) => assert!(err.to_string().contains("Windows process handle")),
        }
    }

    #[test]
    fn platform_capabilities_report_backend_name() {
        let capabilities = platform_capabilities();

        #[cfg(target_os = "macos")]
        assert_eq!(capabilities.backend, "macos_sandbox_exec");

        #[cfg(target_os = "linux")]
        assert_eq!(capabilities.backend, "linux_landlock_seccomp");

        #[cfg(target_os = "windows")]
        assert_eq!(capabilities.backend, "windows_appcontainer");
    }

    #[test]
    fn windows_first_release_capability_contract_is_explicit() {
        let capabilities = platform_capabilities();

        if cfg!(target_os = "windows") {
            assert!(capabilities.execution_supported);
            assert!(capabilities.filesystem_strict);
            assert!(capabilities.network_deny_all);
            assert!(!capabilities.network_allowlist);
            assert!(!capabilities.ipc);
            assert!(capabilities.background_process_tree_cleanup);
        }
    }

    #[test]
    fn windows_appcontainer_capability_contract_is_explicit() {
        let capabilities = super::windows_capabilities();

        assert_eq!(capabilities.backend, "windows_appcontainer");
        assert!(capabilities.execution_supported);
        assert!(capabilities.filesystem_strict);
        assert!(capabilities.network_deny_all);
        assert!(!capabilities.network_allowlist);
        assert!(!capabilities.ipc);
        assert!(capabilities.background_process_tree_cleanup);
    }

    #[test]
    fn macos_capability_contract_is_explicit() {
        let capabilities = super::macos_capabilities();

        assert_eq!(capabilities.backend, "macos_sandbox_exec");
        assert!(capabilities.execution_supported);
        assert!(!capabilities.filesystem_strict);
        assert!(capabilities.network_deny_all);
        assert!(capabilities.network_allowlist);
        assert!(capabilities.ipc);
        assert!(!capabilities.background_process_tree_cleanup);
    }

    #[test]
    fn linux_capability_contract_is_explicit() {
        let capabilities = super::linux_capabilities();

        assert_eq!(capabilities.backend, "linux_landlock_seccomp");
        assert!(capabilities.execution_supported);
        assert!(capabilities.filesystem_strict);
        assert!(capabilities.network_deny_all);
        assert!(capabilities.network_allowlist);
        assert!(capabilities.ipc);
        assert!(!capabilities.background_process_tree_cleanup);
    }

    #[test]
    fn active_platform_capability_contract_is_explicit() {
        let capabilities = platform_capabilities();

        #[cfg(target_os = "macos")]
        assert_eq!(
            capabilities,
            super::PlatformCapabilities {
                backend: "macos_sandbox_exec",
                execution_supported: true,
                filesystem_strict: false,
                network_deny_all: true,
                network_allowlist: true,
                ipc: true,
                background_process_tree_cleanup: false,
            }
        );

        #[cfg(target_os = "linux")]
        assert_eq!(
            capabilities,
            super::PlatformCapabilities {
                backend: "linux_landlock_seccomp",
                execution_supported: true,
                filesystem_strict: true,
                network_deny_all: true,
                network_allowlist: true,
                ipc: true,
                background_process_tree_cleanup: false,
            }
        );

        #[cfg(target_os = "windows")]
        assert_eq!(
            capabilities,
            super::PlatformCapabilities {
                backend: "windows_appcontainer",
                execution_supported: true,
                filesystem_strict: true,
                network_deny_all: true,
                network_allowlist: false,
                ipc: false,
                background_process_tree_cleanup: true,
            }
        );
    }
}
