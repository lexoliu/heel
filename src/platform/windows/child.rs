//! The process handle the Windows backend produces.
//!
//! The launcher returns a process identifier and pipe handles, but keeps its own
//! process handle private and its `wait` consumes the value, so it cannot serve
//! `try_wait` or `kill`. This opens a handle of its own instead. The launcher's
//! value is kept alive alongside it for two reasons: it owns the job object,
//! whose closure kills the process tree, and while it holds a process handle the
//! kernel will not reuse the identifier.

use std::fs::File;
use std::io;
use std::os::windows::process::ExitStatusExt;
use std::process::ExitStatus;

use rappct::launch::LaunchedIo;
use rappct::net::LoopbackExemptionGuard;
use windows::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE, WAIT_FAILED, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows::Win32::System::JobObjects::TerminateJobObject;
use windows::Win32::System::Threading::{
    GetExitCodeProcess, INFINITE, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION,
    PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};

use crate::platform::child::ProcessHandle;

/// An owned process handle, closed when it goes out of scope.
#[derive(Debug)]
struct OwnedProcess(HANDLE);

// SAFETY: a process handle is not tied to the thread that opened it; the kernel
// permits any thread to wait on, query or terminate through it.
unsafe impl Send for OwnedProcess {}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        // SAFETY: the handle came from `OpenProcess` and is closed exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// A process running inside an AppContainer.
#[derive(Debug)]
pub(crate) struct AppContainerChild {
    /// Owns the job object and the launcher's process handle; see the module
    /// comment for why it is kept rather than destructured.
    launched: LaunchedIo,
    process: OwnedProcess,
    /// Held for the life of the process: dropping it withdraws the container's
    /// permission to reach the proxy on loopback.
    _loopback: Option<LoopbackExemptionGuard>,
    pid: u32,
}

impl AppContainerChild {
    /// Adopt a freshly launched process.
    pub(crate) fn new(
        launched: LaunchedIo,
        loopback: Option<LoopbackExemptionGuard>,
    ) -> io::Result<Self> {
        let pid = launched.pid;

        // SAFETY: `pid` names the process just launched, which the value in
        // `launched` still holds a handle to, so the identifier is still valid.
        let handle = unsafe {
            OpenProcess(
                PROCESS_ACCESS_RIGHTS(
                    PROCESS_QUERY_INFORMATION.0 | PROCESS_TERMINATE.0 | SYNCHRONIZE.0,
                ),
                false,
                pid,
            )
        }
        .map_err(|source| {
            io::Error::other(format!("cannot open the sandboxed process {pid}: {source}"))
        })?;

        Ok(Self {
            launched,
            process: OwnedProcess(handle),
            _loopback: loopback,
            pid,
        })
    }

    /// The process's exit code, or `None` while it is still running.
    fn exit_code(&self) -> io::Result<Option<u32>> {
        let mut code = 0u32;
        // SAFETY: the handle is open and `code` is a valid destination.
        unsafe { GetExitCodeProcess(self.process.0, &mut code) }
            .map_err(|source| io::Error::other(format!("cannot read the exit code: {source}")))?;

        // A process that genuinely exits with this value is indistinguishable
        // from one still running; Windows offers no way to tell them apart.
        if code == STILL_ACTIVE.0 as u32 {
            return Ok(None);
        }
        Ok(Some(code))
    }

    /// Wait for the process, for at most `timeout_ms`.
    fn wait_for(&self, timeout_ms: u32) -> io::Result<bool> {
        // SAFETY: the handle is open and waitable.
        let result = unsafe { WaitForSingleObject(self.process.0, timeout_ms) };
        if result == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(result != WAIT_TIMEOUT)
    }
}

impl ProcessHandle for AppContainerChild {
    fn id(&self) -> u32 {
        self.pid
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        self.wait_for(INFINITE)?;
        let code = self.exit_code()?.unwrap_or_default();
        Ok(ExitStatus::from_raw(code))
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if !self.wait_for(0)? {
            return Ok(None);
        }
        Ok(self.exit_code()?.map(ExitStatus::from_raw))
    }

    fn kill(&mut self) -> io::Result<()> {
        // Terminating the job takes the whole process tree, which is what the
        // other backends do by signalling a process group. Without a job there
        // is only the process itself to terminate.
        let terminated = match self.launched.job_guard.as_ref() {
            // SAFETY: the guard owns the job handle for as long as it lives.
            Some(job) => unsafe { TerminateJobObject(job.as_handle(), 1) },
            // SAFETY: the handle is open and was opened with PROCESS_TERMINATE.
            None => unsafe { TerminateProcess(self.process.0, 1) },
        };

        // A process that has already exited cannot be terminated, which is the
        // state this call is trying to reach.
        if terminated.is_err() && self.exit_code()?.is_none() {
            return Err(io::Error::other("cannot terminate the sandboxed process"));
        }

        self.wait_for(INFINITE)?;
        Ok(())
    }

    fn stdin(&mut self) -> &mut Option<File> {
        &mut self.launched.stdin
    }

    fn stdout(&mut self) -> &mut Option<File> {
        &mut self.launched.stdout
    }

    fn stderr(&mut self) -> &mut Option<File> {
        &mut self.launched.stderr
    }
}
