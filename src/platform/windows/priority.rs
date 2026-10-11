//! Scheduling priority for the AppContainer backend.
//!
//! The priority is a limit on the sandbox's job object rather than a setting
//! on the one process: a job's priority class applies to every process in it,
//! and a process created inside the job joins it, so the whole tree is covered
//! by one call and none of its members can raise itself back out.
//!
//! Only the CPU half is applied. Windows exposes no documented way to set
//! another process's I/O priority — `SetPriorityClass` accepts
//! `PROCESS_MODE_BACKGROUND_BEGIN` only for the calling process, and
//! `NtSetInformationProcess(ProcessIoPriority)` is undocumented and may change
//! between releases, which is not something a sandbox should depend on — so a
//! lowered [`IoPriority`] is reported and left unapplied rather than reached
//! for through an unsupported call.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::{
    JOB_OBJECT_LIMIT_PRIORITY_CLASS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
};
use windows::Win32::System::Threading::{BELOW_NORMAL_PRIORITY_CLASS, IDLE_PRIORITY_CLASS};

use crate::error::{Error, Result};
use crate::priority::{CpuPriority, IoPriority, ProcessPriority};

/// The lowest nice level that maps to the idle class.
///
/// Unix spreads the reduction over nineteen steps and Windows over two
/// classes, so the range is split: the gentler half asks to lose only to
/// ordinary work, the lower half to run on whatever is left.
const IDLE_FROM_NICE: u8 = 15;

/// The priority class a configured CPU priority asks for, if any.
fn priority_class(cpu: CpuPriority) -> Option<u32> {
    match cpu {
        CpuPriority::Normal => None,
        CpuPriority::Nice(level) if level.get() < IDLE_FROM_NICE => {
            Some(BELOW_NORMAL_PRIORITY_CLASS.0)
        }
        CpuPriority::Nice(_) => Some(IDLE_PRIORITY_CLASS.0),
    }
}

/// Lower the priority of everything in `job`.
///
/// # Errors
///
/// Returns an error if the job's existing limits cannot be read back or the
/// priority class cannot be added to them.
pub(crate) fn apply(job: HANDLE, priority: ProcessPriority) -> Result<()> {
    if priority.io() != IoPriority::Normal {
        tracing::warn!(
            io_priority = ?priority.io(),
            "sandbox: Windows has no documented API for another process's I/O priority; \
             only the CPU priority is applied"
        );
    }

    let Some(class) = priority_class(priority.cpu()) else {
        return Ok(());
    };

    // The job already carries the memory limit and kill-on-close, and one
    // `SetInformationJobObject` replaces every limit in the structure, so the
    // current set is read back and the priority class added to it.
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let size =
        u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).map_err(|source| {
            Error::InitFailed(format!("job limit structure is too large: {source}"))
        })?;

    // SAFETY: `info` is a correctly sized, initialized destination for the
    // information class named alongside it.
    unsafe {
        QueryInformationJobObject(
            Some(job),
            JobObjectExtendedLimitInformation,
            (&raw mut info).cast(),
            size,
            None,
        )
    }
    .map_err(|source| {
        Error::InitFailed(format!("cannot read the sandbox job's limits: {source}"))
    })?;

    info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PRIORITY_CLASS;
    info.BasicLimitInformation.PriorityClass = class;

    // SAFETY: as above, with the structure now holding the limits to install.
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            size,
        )
    }
    .map_err(|source| {
        Error::InitFailed(format!(
            "cannot lower the sandbox job's priority class to {class:#x}: {source}"
        ))
    })?;

    tracing::debug!(priority_class = class, "sandbox: job priority lowered");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::priority::NiceLevel;

    #[test]
    fn a_normal_priority_asks_for_no_class() {
        assert_eq!(priority_class(CpuPriority::Normal), None);
    }

    #[test]
    fn the_nice_range_is_split_between_the_two_classes() {
        let class =
            |level: u8| priority_class(CpuPriority::Nice(NiceLevel::new(level).unwrap())).unwrap();

        assert_eq!(class(1), BELOW_NORMAL_PRIORITY_CLASS.0);
        assert_eq!(class(14), BELOW_NORMAL_PRIORITY_CLASS.0);
        assert_eq!(class(15), IDLE_PRIORITY_CLASS.0);
        assert_eq!(class(19), IDLE_PRIORITY_CLASS.0);
    }
}
