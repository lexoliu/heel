//! The process handle the Windows backend produces.
//!
//! The launcher returns the process and job handles it created, so the child
//! owns them directly — no second `OpenProcess`, and the job is the one the
//! process was assigned to at creation. The job handle is also what carries
//! the kill: closing it ends the whole tree, and `kill` asks it to.

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt;
use std::process::ExitStatus;

use windows::Win32::Foundation::{HANDLE, STILL_ACTIVE, WAIT_FAILED, WAIT_TIMEOUT};
use windows::Win32::System::JobObjects::TerminateJobObject;
use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};

use super::launch::Launched;
use super::loopback::LoopbackExemption;
use crate::platform::child::ProcessHandle;

/// A process running inside an AppContainer.
#[derive(Debug)]
pub(crate) struct AppContainerChild {
    /// The process itself, adopted from `PROCESS_INFORMATION`.
    process: OwnedHandle,
    /// The job the process was assigned to at creation: kill-on-close.
    job: OwnedHandle,
    /// The parent's ends of the pipes, when the launch asked for them.
    stdin: Option<File>,
    /// Same, for standard output.
    stdout: Option<File>,
    /// Same, for standard error.
    stderr: Option<File>,
    /// Held for the life of the process: dropping it withdraws the
    /// container's permission to reach the proxy on loopback.
    _loopback: Option<LoopbackExemption>,
    pid: u32,
}

impl AppContainerChild {
    /// Adopt a freshly launched process.
    pub(crate) fn new(launched: Launched, loopback: Option<LoopbackExemption>) -> Self {
        Self {
            process: launched.process,
            job: launched.job,
            stdin: launched.stdin,
            stdout: launched.stdout,
            stderr: launched.stderr,
            _loopback: loopback,
            pid: launched.pid,
        }
    }

    /// The process's exit code, or `None` while it is still running.
    fn exit_code(&self) -> io::Result<Option<u32>> {
        let mut code = 0u32;
        // SAFETY: the handle is open and `code` is a valid destination.
        unsafe { GetExitCodeProcess(self.process_handle(), &mut code) }
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
        let result = unsafe { WaitForSingleObject(self.process_handle(), timeout_ms) };
        if result == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(result != WAIT_TIMEOUT)
    }

    /// The process handle in `HANDLE` form.
    fn process_handle(&self) -> HANDLE {
        HANDLE(self.process.as_raw_handle())
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
        // other backends do by signalling a process group.
        // SAFETY: the guard owns the job handle for as long as it lives.
        let terminated = unsafe { TerminateJobObject(HANDLE(self.job.as_raw_handle()), 1) };

        // A process that has already exited cannot be terminated, which is the
        // state this call is trying to reach.
        if terminated.is_err() && self.exit_code()?.is_none() {
            return Err(io::Error::other("cannot terminate the sandboxed process"));
        }

        self.wait_for(INFINITE)?;
        Ok(())
    }

    fn stdin(&mut self) -> &mut Option<File> {
        &mut self.stdin
    }

    fn stdout(&mut self) -> &mut Option<File> {
        &mut self.stdout
    }

    fn stderr(&mut self) -> &mut Option<File> {
        &mut self.stderr
    }
}
