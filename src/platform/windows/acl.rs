//! Access control entries for the container, with inheritance spelled out.
//!
//! Windows uses one bit for two things: on a file it means "may be run", and on
//! a directory it means "may be entered". A container that cannot enter its own
//! working directory cannot be started there, and a container that may run what
//! it writes there is not sandboxed, so the two cases need different entries:
//! one inherited by subdirectories, carrying traverse, and one inherited by
//! files, without execute.
//!
//! That distinction is why these calls are made directly rather than through
//! `rappct`, whose ACL helper applies a single mask to a directory and
//! everything beneath it.

use std::io;
use std::path::Path;

use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    GetSecurityInfo, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
    OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID,
};
use windows::core::{PCWSTR, PWSTR};

/// What one entry grants, and to what it applies.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry {
    /// The access mask to grant.
    pub(crate) access: u32,
    /// Which objects the entry reaches.
    pub(crate) applies_to: Scope,
}

/// Which objects an entry applies to.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Scope {
    /// The path itself, and nothing beneath it.
    ThisOnly,
    /// The directory itself and every directory beneath it, but no file.
    Directories,
    /// Every file beneath the directory, but not the directory itself.
    Files,
}

impl Scope {
    fn flags(self) -> ACE_FLAGS {
        match self {
            // No inheritance: the entry reaches this object alone.
            Self::ThisOnly => ACE_FLAGS(0),
            // Without INHERIT_ONLY the entry also applies to the directory the
            // rule is set on, which is what lets the container enter it.
            Self::Directories => CONTAINER_INHERIT_ACE,
            Self::Files => ACE_FLAGS(OBJECT_INHERIT_ACE.0 | INHERIT_ONLY_ACE.0),
        }
    }
}

/// A `LocalAlloc` allocation released when it goes out of scope.
struct LocalBuffer(*mut core::ffi::c_void);

impl Drop for LocalBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to return
            // `LocalAlloc` memory, and is freed exactly once.
            unsafe { LocalFree(Some(HLOCAL(self.0))) };
        }
    }
}

/// Convert a string SID into the form the ACL APIs take.
fn parse_sid(sddl: &str) -> io::Result<(LocalBuffer, PSID)> {
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid = PSID(std::ptr::null_mut());

    // SAFETY: `wide` is NUL-terminated and `sid` is a valid destination.
    unsafe { ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut sid) }
        .map_err(|source| io::Error::other(format!("cannot parse the container SID: {source}")))?;

    Ok((LocalBuffer(sid.0), sid))
}

/// Add `access` for `sid` to the kernel object named `name`.
///
/// Devices live outside the filesystem tree, so the name is handed to the
/// named security APIs verbatim — nothing resolves it — and the grant applies
/// to the object itself, the only scope a device has.
pub(crate) fn grant_object(name: &str, sid: &str, access: u32) -> io::Result<()> {
    apply(
        name,
        sid,
        &[Entry {
            access,
            applies_to: Scope::ThisOnly,
        }],
    )
}

/// Add `access` for `sid` to the kernel object `handle` refers to.
///
/// Some kernel objects — a named pipe is the case that needs this — have no
/// name the security APIs accept, so the grant goes through a handle instead.
/// The object itself is the only scope it has.
pub(crate) fn grant_handle(handle: HANDLE, sddl: &str, access: u32) -> io::Result<()> {
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let mut current: *mut ACL = std::ptr::null_mut();

    // SAFETY: the out-parameters are valid destinations.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut current),
            None,
            Some(&mut descriptor),
        )
    };
    if status.is_err() {
        return Err(io::Error::other(format!(
            "cannot read the access control list of the kernel object: {status:?}"
        )));
    }
    let _descriptor = LocalBuffer(descriptor.0);

    let updated = merge(
        sddl,
        current,
        &[Entry {
            access,
            applies_to: Scope::ThisOnly,
        }],
        "the kernel object",
    )?;

    // SAFETY: `updated` is the list just built, valid while the guard lives.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(updated.0.cast()),
            None,
        )
    };
    drop(updated);

    if status.is_err() {
        return Err(io::Error::other(format!(
            "cannot apply the access control list to the kernel object: {status:?}"
        )));
    }

    Ok(())
}

/// Add `entries` for `sid` to the access control list of `path`.
///
/// Existing entries are kept: the rule is added to what is already there rather
/// than replacing it, so nothing the machine or the user already relies on is
/// removed.
///
/// The named security APIs reject object names deeper than `MAX_PATH` unless
/// they are spelled verbatim, and a walked tree reaches children deeper than
/// that. Resolving the path first hands them the `\\?\` form they accept at
/// any depth, while the errors keep naming the path the caller asked for.
pub(crate) fn grant(path: &Path, sid: &str, entries: &[Entry]) -> io::Result<()> {
    let resolved = std::fs::canonicalize(path).map_err(|source| {
        io::Error::other(format!("cannot resolve {}: {source}", path.display()))
    })?;
    apply(&resolved.to_string_lossy(), sid, entries)
}

/// Merge `entries` for `sddl` into `current`, producing a new list.
///
/// The returned ACL is `LocalAlloc` memory the caller frees, and `object`
/// names what is being edited for the error.
fn merge(
    sddl: &str,
    current: *mut ACL,
    entries: &[Entry],
    object: &str,
) -> io::Result<LocalBuffer> {
    let (_sid_buffer, sid) = parse_sid(sddl)?;

    let trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: PWSTR(sid.0.cast()),
        ..Default::default()
    };

    let access: Vec<EXPLICIT_ACCESS_W> = entries
        .iter()
        .map(|entry| EXPLICIT_ACCESS_W {
            grfAccessPermissions: entry.access,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: entry.applies_to.flags(),
            Trustee: trustee,
        })
        .collect();

    let mut updated: *mut ACL = std::ptr::null_mut();
    // SAFETY: `access` outlives the call and `current` is the caller's list.
    let status = unsafe { SetEntriesInAclW(Some(&access), Some(current), &mut updated) };
    if status.is_err() {
        return Err(io::Error::other(format!(
            "cannot build the access control list for {object}: {status:?}"
        )));
    }
    Ok(LocalBuffer(updated.cast()))
}

/// Add `entries` for `sid` to the object `name` refers to.
///
/// `name` reaches the named security APIs as given: a filesystem path already
/// spelled verbatim, or an object name such as a device path.
fn apply(name: &str, sddl: &str, entries: &[Entry]) -> io::Result<()> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let mut current: *mut ACL = std::ptr::null_mut();

    // SAFETY: the path is NUL-terminated and the out-parameters are valid.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut current),
            None,
            &mut descriptor,
        )
    };
    if status.is_err() {
        return Err(io::Error::other(format!(
            "cannot read the access control list of {name}: {status:?}"
        )));
    }
    let _descriptor = LocalBuffer(descriptor.0);

    let updated = merge(sddl, current, entries, name)?;

    // SAFETY: `updated` is the list just built, valid while the guard lives.
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(updated.0.cast()),
            None,
        )
    };
    drop(updated);

    if status.is_err() {
        return Err(io::Error::other(format!(
            "cannot apply the access control list to {name}: {status:?}"
        )));
    }

    Ok(())
}
