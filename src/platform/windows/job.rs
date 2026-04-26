use std::mem::size_of;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};

use crate::error::{Error, Result};

pub(crate) struct JobGuard {
    handle: HANDLE,
}

unsafe impl Send for JobGuard {}

impl JobGuard {
    pub(crate) fn new() -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(None, None) }
            .map_err(|error| Error::FfiError(format!("CreateJobObjectW failed: {error}")))?;
        if handle.is_invalid() || handle.0.is_null() {
            return Err(Error::FfiError(
                "CreateJobObjectW returned an invalid job handle".to_string(),
            ));
        }

        let guard = Self { handle };
        guard.enable_kill_on_close()?;
        Ok(guard)
    }

    pub(crate) fn assign_process(&self, process: HANDLE) -> Result<()> {
        unsafe {
            AssignProcessToJobObject(self.handle, process).map_err(|error| {
                Error::FfiError(format!("AssignProcessToJobObject failed: {error}"))
            })
        }
    }

    pub(crate) fn terminate(&self, exit_code: u32) -> Result<()> {
        unsafe {
            TerminateJobObject(self.handle, exit_code)
                .map_err(|error| Error::FfiError(format!("TerminateJobObject failed: {error}")))
        }
    }

    fn enable_kill_on_close(&self) -> Result<()> {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|error| {
                Error::FfiError(format!(
                    "SetInformationJobObject kill-on-close failed: {error}"
                ))
            })
        }
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        if !self.handle.is_invalid()
            && !self.handle.0.is_null()
            && let Err(error) = unsafe { CloseHandle(self.handle) }
        {
            tracing::warn!("failed to close Windows job handle: {error}");
        }
    }
}
