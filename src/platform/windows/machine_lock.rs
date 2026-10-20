//! A machine-wide mutex serializing sections that race across heel processes.
//!
//! Processes in different sessions can touch the same machine-visible state at
//! once — a shared directory's access control list, a named AppContainer
//! profile — and the calls involved report the collision as a failure rather
//! than an ordering. A `Global\` mutex gives a section one holder at a time;
//! its name chooses what is serialized, so sections over different objects
//! never wait on each other. No path holds two differently named mutexes at
//! once — the profile open's guard is dropped before grant reconciliation
//! takes the ACL lock — so they need no ordering between them.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{HANDLE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{
    CreateMutexExW, INFINITE, MUTEX_MODIFY_STATE, ReleaseMutex, SYNCHRONIZATION_SYNCHRONIZE,
    WaitForSingleObject,
};
use windows::core::PCWSTR;

use super::LocalBuffer;

/// SYSTEM and Administrators need full access; Authenticated Users need only
/// the rights to wait and release. A standard-user probe could create a Global
/// mutex, but the default DACL denied opening an administrator-created one
/// with error 5; AppContainer tokens receive no rights from this descriptor.
const MUTEX_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100001;;;AU)";

/// Owns an acquired mutex and releases it before closing the handle.
pub(crate) struct Guard {
    /// The name acquisition was made under, for the release-failure report.
    name: String,
    handle: OwnedHandle,
}

impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: `handle` is the mutex acquired by this thread and remains
        // open until the field is dropped after this method returns.
        if let Err(source) = unsafe { ReleaseMutex(HANDLE(self.handle.as_raw_handle())) } {
            tracing::error!(mutex = %self.name, %source, "cannot release the machine-wide mutex");
        }
    }
}

/// Acquire the machine-wide mutex `name`, creating it when absent.
///
/// `name` is a full kernel object name — `Global\…` for one shared across
/// sessions. `WAIT_ABANDONED` still grants ownership: the prior holder died
/// mid-section, but everything this serializes is atomic or re-derivable —
/// an ACL write is atomic for its object, and a profile open is create-or-open
/// work the next holder redoes whole — so there is no partial state to repair.
pub(crate) fn lock(name: &str) -> io::Result<Guard> {
    let wide_sddl: Vec<u16> = MUTEX_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // SAFETY: `wide_sddl` is NUL-terminated and `descriptor` is a valid
    // out-parameter for the LocalAlloc-backed security descriptor.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide_sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|source| {
        io::Error::other(format!(
            "cannot create the security descriptor for {name}: {source}"
        ))
    })?;
    let _descriptor = LocalBuffer(descriptor.0.cast());
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: `attributes` and its descriptor remain alive through the call,
    // `wide_name` is NUL-terminated, and the requested rights match the DACL.
    let handle = unsafe {
        CreateMutexExW(
            Some(&attributes),
            PCWSTR(wide_name.as_ptr()),
            0,
            SYNCHRONIZATION_SYNCHRONIZE.0 | MUTEX_MODIFY_STATE.0,
        )
    }
    .map_err(|source| io::Error::other(format!("CreateMutexExW failed for {name}: {source}")))?;
    // SAFETY: the handle was returned by CreateMutexExW and is transferred
    // to this owner exactly once.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0.cast()) };

    // SAFETY: `handle` is an open mutex handle owned by this guard attempt.
    let result = unsafe { WaitForSingleObject(HANDLE(handle.as_raw_handle()), INFINITE) };
    match result {
        WAIT_OBJECT_0 => {}
        WAIT_ABANDONED => {
            // The previous holder died mid-section, but what it guarded needs
            // no repair: an ACL write is atomic for its object, and a profile
            // open is create-or-open work this holder redoes whole.
        }
        WAIT_FAILED => {
            return Err(io::Error::other(format!(
                "WaitForSingleObject failed for {name}: {}",
                io::Error::last_os_error()
            )));
        }
        result => {
            return Err(io::Error::other(format!(
                "WaitForSingleObject returned {result:?} for {name}"
            )));
        }
    }

    Ok(Guard {
        name: name.to_owned(),
        handle,
    })
}
