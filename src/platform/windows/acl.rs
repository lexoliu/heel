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
//! a generic ACL helper, which applies a single mask to a directory and
//! everything beneath it.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use windows::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL, LocalFree, WAIT_ABANDONED, WAIT_FAILED,
    WAIT_OBJECT_0, WIN32_ERROR,
};
#[cfg(test)]
use windows::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, GetSecurityInfo, REVOKE_ACCESS,
    SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SetEntriesInAclW,
    SetNamedSecurityInfoW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACE_FLAGS, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, EqualSid, GENERIC_MAPPING, GetAce, GetSecurityDescriptorControl,
    INHERIT_ONLY_ACE, INHERITED_ACE, InitializeSecurityDescriptor, MapGenericMask,
    OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SE_DACL_AUTO_INHERIT_REQ,
    SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SECURITY_DESCRIPTOR_CONTROL, SetFileSecurityW, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl,
};
#[cfg(test)]
use windows::Win32::Storage::FileSystem::FILE_TRAVERSE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ALL_ACCESS, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    WRITE_DAC,
};
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
};
use windows::Win32::System::Threading::{
    CreateMutexExW, INFINITE, MUTEX_MODIFY_STATE, ReleaseMutex, SYNCHRONIZATION_SYNCHRONIZE,
    WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

/// A machine-wide name because heel processes in different sessions can grant
/// the same shared directory and must serialize its ACL update.
const ACL_UPDATE_MUTEX_NAME: &str = "Global\\heel-acl-update";

/// SYSTEM and Administrators need full access; Authenticated Users need only
/// the rights to wait and release. A standard-user probe could create a Global
/// mutex, but the default DACL denied opening an administrator-created one
/// with error 5; AppContainer tokens receive no rights from this descriptor.
const ACL_UPDATE_MUTEX_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100001;;;AU)";

/// Owns an acquired mutex and releases it before closing the handle.
pub(crate) struct Guard {
    handle: OwnedHandle,
}

impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: `handle` is the mutex acquired by this thread and remains
        // open until the field is dropped after this method returns.
        if let Err(source) = unsafe { ReleaseMutex(HANDLE(self.handle.as_raw_handle())) } {
            tracing::error!(%source, "cannot release the ACL update mutex");
        }
    }
}

/// Acquire the machine-wide lock around an ACL read, merge, write, and the
/// `SetNamedSecurityInfoW` propagation that applies the write to a tree.
///
/// `WAIT_ABANDONED` still grants ownership: the prior holder died, but each
/// ACL write is atomic for its object, so there is no partial list to repair.
fn acquire() -> io::Result<Guard> {
    let wide_sddl: Vec<u16> = ACL_UPDATE_MUTEX_SDDL
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
            "cannot create the ACL update mutex security descriptor: {source}"
        ))
    })?;
    let _descriptor = LocalBuffer(descriptor.0.cast());
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let wide_name: Vec<u16> = ACL_UPDATE_MUTEX_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

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
    .map_err(|source| {
        io::Error::other(format!(
            "CreateMutexExW failed for {ACL_UPDATE_MUTEX_NAME}: {source}"
        ))
    })?;
    // SAFETY: the handle was returned by CreateMutexExW and is transferred
    // to this owner exactly once.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0.cast()) };

    // SAFETY: `handle` is an open mutex handle owned by this guard attempt.
    let result = unsafe { WaitForSingleObject(HANDLE(handle.as_raw_handle()), INFINITE) };
    match result {
        WAIT_OBJECT_0 => {}
        WAIT_ABANDONED => {
            // The previous holder died. Each ACL write is atomic per object,
            // so there is no half-written list for this holder to repair.
        }
        WAIT_FAILED => {
            return Err(io::Error::other(format!(
                "WaitForSingleObject failed for {ACL_UPDATE_MUTEX_NAME}: {}",
                io::Error::last_os_error()
            )));
        }
        result => {
            return Err(io::Error::other(format!(
                "WaitForSingleObject returned {result:?} for {ACL_UPDATE_MUTEX_NAME}"
            )));
        }
    }

    Ok(Guard { handle })
}

/// Acquire the machine-wide lock used by ACL mutations.
pub(crate) fn lock() -> io::Result<Guard> {
    acquire()
}

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
        SE_FILE_OBJECT,
    )
}

/// Add `access` for `sid` to the named pipe `name` refers to.
///
/// Neither usual route reaches the list: the object-name APIs reject pipe
/// paths outright, and the handles the listener was built from were opened
/// without `WRITE_DAC` — no call widens the rights of an existing handle.
/// What does reach it is a client connection asking for `WRITE_DAC` itself,
/// which the default list grants the pipe's owner. The server sees the
/// connection come and go unanswered, which it already tolerates.
pub(crate) fn grant_pipe(name: &str, sid: &str, access: u32) -> io::Result<()> {
    let path = format!("\\\\.\\pipe\\{name}");
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: `wide` is NUL-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | WRITE_DAC.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|source| io::Error::other(format!("cannot open the named pipe {path}: {source}")))?;

    // SAFETY: the handle came from the call above and is closed exactly once.
    let _handle = unsafe { OwnedHandle::from_raw_handle(handle.0.cast()) };
    grant_handle(handle, sid, access)
}

/// Run a `Get*SecurityInfo` call until it answers or fails for real.
///
/// The calls are documented not to handle a security descriptor that
/// changes mid-call: the object's list can move between the size they
/// first query and the read they then make, which is reported as
/// `ERROR_INSUFFICIENT_BUFFER`. Heel's mutex serializes its
/// read-modify-write updates, but read-only access checks and writers outside
/// heel can still race a read — and the API's answer is to ask again. The
/// loop stays bounded so a descriptor that cannot be read still fails after
/// `ATTEMPTS` tries.
fn reread(object: &str, mut attempt: impl FnMut() -> WIN32_ERROR) -> io::Result<()> {
    const ATTEMPTS: u32 = 5;

    let mut status = attempt();
    let mut remaining = ATTEMPTS - 1;
    while status == ERROR_INSUFFICIENT_BUFFER && remaining > 0 {
        remaining -= 1;
        std::thread::sleep(std::time::Duration::from_millis(1));
        status = attempt();
    }

    if status.is_err() {
        return Err(io::Error::other(format!(
            "cannot read the access control list of {object}: {status:?}"
        )));
    }
    Ok(())
}

/// Add `access` for `sid` to the kernel object `handle` refers to.
///
/// The handle must already carry `WRITE_DAC`, which the caller arranges by
/// how it opens the object. The object itself is the only scope it has.
fn grant_handle(handle: HANDLE, sddl: &str, access: u32) -> io::Result<()> {
    let _guard = acquire()?;
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let mut current: *mut ACL = std::ptr::null_mut();

    reread("the kernel object", || {
        descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        current = std::ptr::null_mut();
        // SAFETY: the out-parameters are valid destinations.
        unsafe {
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
        }
    })?;
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
/// The resolved name the entries were written to is returned so the caller
/// can hand the same name to `revoke` when the sandbox is dropped.
pub(crate) fn grant(path: &Path, sid: &str, entries: &[Entry]) -> io::Result<String> {
    let name = resolve(path)?;
    apply(&name, sid, entries, SE_FILE_OBJECT)?;
    Ok(name)
}

/// Add `access` for `sid` to the object at `path` alone, without touching
/// anything beneath it.
///
/// `SetNamedSecurityInfoW` recomputes inheritance through the whole tree
/// below a directory whenever it writes the directory's list, whether or not
/// the entries it adds are inheritable. A traverse grant on an ancestor such
/// as the user profile therefore walked the entire profile, once per grant
/// and per sandbox, holding handles on whatever it passed. An entry that
/// applies to the object alone changes nothing a child inherits, so it is
/// stored with `SetFileSecurityW`, which writes the object's own descriptor
/// and propagates nothing. The list keeps its protected and auto-inherited
/// bits, so how it relates to its parent is unchanged.
///
/// The resolved name the entry was written to is returned, as `grant`
/// returns it, for the matching `revoke_this_only` call.
pub(crate) fn grant_this_only(path: &Path, sid: &str, access: u32) -> io::Result<String> {
    let _guard = acquire()?;
    let name = resolve(path)?;
    let (descriptor, current) = read_dacl(&name, SE_FILE_OBJECT)?;
    let updated = merge(
        sid,
        current,
        &[Entry {
            access,
            applies_to: Scope::ThisOnly,
        }],
        &name,
    )?;
    write_file_dacl(&name, &descriptor, updated)?;
    Ok(name)
}

/// Add inheritable entries to `path` without propagating them to its children.
#[cfg(test)]
pub(crate) fn add_without_propagation(path: &Path, sid: &str, entries: &[Entry]) -> io::Result<()> {
    let _guard = acquire()?;
    let name = resolve(path)?;
    let (descriptor, current) = read_dacl(&name, SE_FILE_OBJECT)?;
    let updated = merge(sid, current, entries, &name)?;
    write_file_dacl(&name, &descriptor, updated)
}

/// Remove every entry `sddl` holds on the object `name` refers to.
///
/// The machine-wide mutex lets heel's concurrent grants finish before the
/// list is re-read, so this removal drops only the named trustee's entries
/// from the latest list and preserves other SIDs. Writers outside heel do
/// not take the mutex. `SetNamedSecurityInfoW` then propagates the removal
/// through the tree the same way the grant propagated the entry.
pub(crate) fn revoke(name: &str, sddl: &str) -> io::Result<()> {
    let _guard = acquire()?;
    let (_descriptor, current) = read_dacl(name, SE_FILE_OBJECT)?;
    let updated = without(sddl, current, name)?;
    write_dacl(name, updated, SE_FILE_OBJECT)
}

/// Remove every entry `sddl` holds on the file `name` refers to, touching
/// nothing beneath it — the counterpart of `grant_this_only`.
pub(crate) fn revoke_this_only(name: &str, sddl: &str) -> io::Result<()> {
    let _guard = acquire()?;
    let (descriptor, current) = read_dacl(name, SE_FILE_OBJECT)?;
    let updated = without(sddl, current, name)?;
    write_file_dacl(name, &descriptor, updated)
}

/// The rights named `trustees` receive from the object's own DACL on `path`.
///
/// Each trustee is a SID in `S-…` form. `GetEffectiveRightsFromAclW` expands
/// group membership, so it counted Everyone and Users ACEs that the kernel's
/// AppContainer access check ignores. The token carries its package SID,
/// capability SIDs, and ALL APPLICATION PACKAGES instead. Inherited ACEs that
/// apply to this object are already in its DACL; inherit-only ACEs are skipped
/// because they do not apply to the object itself.
pub(crate) fn effective_rights(path: &Path, trustees: &[&str]) -> io::Result<u32> {
    let name = resolve(path)?;
    let (_descriptor, current) = read_dacl(&name, SE_FILE_OBJECT)?;

    // SetSecurityDescriptorDacl documents that a NULL DACL allows all access;
    // an absent list therefore cannot be treated like an empty, deny-all DACL.
    if current.is_null() {
        return Ok(u32::MAX);
    }

    let trustee_sids = trustees
        .iter()
        .map(|trustee| parse_sid(trustee))
        .collect::<io::Result<Vec<_>>>()?;
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ.0,
        GenericWrite: FILE_GENERIC_WRITE.0,
        GenericExecute: FILE_GENERIC_EXECUTE.0,
        GenericAll: FILE_ALL_ACCESS.0,
    };
    // SAFETY: `current` is non-null and points into the descriptor returned
    // by `read_dacl`, which remains alive for this function.
    let ace_count = unsafe { (*current).AceCount };
    let mut granted = 0u32;
    let mut denied = 0u32;

    for index in 0..u32::from(ace_count) {
        let mut raw_ace = std::ptr::null_mut();
        // SAFETY: `current` points into the descriptor kept alive by
        // `_descriptor`, and `raw_ace` is a valid out-parameter.
        unsafe { GetAce(current, index, &mut raw_ace) }.map_err(|source| {
            io::Error::other(format!("cannot read ACE {index} from {name}: {source}"))
        })?;

        // SAFETY: `GetAce` returned a pointer to an ACE in the live DACL.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if ACE_FLAGS(u32::from(header.AceFlags)).contains(INHERIT_ONLY_ACE) {
            continue;
        }

        let (mut mask, ace_sid, allowed) = if header.AceType == ACCESS_ALLOWED_ACE_TYPE as u8 {
            // SAFETY: this ACE type has the ACCESS_ALLOWED_ACE layout.
            let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
            (
                ace.Mask,
                PSID(std::ptr::addr_of!(ace.SidStart).cast_mut().cast()),
                true,
            )
        } else if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            // SAFETY: this ACE type has the ACCESS_DENIED_ACE layout.
            let ace = unsafe { &*raw_ace.cast::<ACCESS_DENIED_ACE>() };
            (
                ace.Mask,
                PSID(std::ptr::addr_of!(ace.SidStart).cast_mut().cast()),
                false,
            )
        } else {
            continue;
        };
        if !trustee_sids.iter().any(|(_, trustee_sid)| {
            // SAFETY: both SIDs are valid and remain alive for this comparison.
            unsafe { EqualSid(ace_sid, *trustee_sid) }.is_ok()
        }) {
            continue;
        }

        // SAFETY: `mapping` is the file mapping and `mask` is a valid in/out
        // access mask for MapGenericMask.
        unsafe { MapGenericMask(&mut mask, &mapping) };
        if allowed {
            granted |= mask & !denied;
        } else {
            denied |= mask & !granted;
        }
    }

    Ok(granted)
}

/// Whether an explicit allow or deny ACE in `name`'s DACL names `sid`.
pub(crate) fn names_trustee(name: &str, sid: &str) -> io::Result<bool> {
    let (_descriptor, current) = read_dacl(name, SE_FILE_OBJECT)?;
    if current.is_null() {
        return Ok(false);
    }
    let (_sid_allocation, sid) = parse_sid(sid)?;

    // SAFETY: `current` points into the descriptor returned by `read_dacl`,
    // which remains alive for this function.
    let ace_count = unsafe { (*current).AceCount };
    for index in 0..u32::from(ace_count) {
        let mut raw_ace = std::ptr::null_mut();
        // SAFETY: `current` points into the descriptor kept alive by
        // `_descriptor`, and `raw_ace` is a valid out-parameter.
        unsafe { GetAce(current, index, &mut raw_ace) }.map_err(|source| {
            io::Error::other(format!("cannot read ACE {index} from {name}: {source}"))
        })?;

        // SAFETY: `GetAce` returned a pointer to an ACE in the live DACL.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if ACE_FLAGS(u32::from(header.AceFlags)).contains(INHERITED_ACE) {
            continue;
        }

        let ace_sid = if header.AceType == ACCESS_ALLOWED_ACE_TYPE as u8 {
            // SAFETY: this ACE type has the ACCESS_ALLOWED_ACE layout.
            let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
            PSID(std::ptr::addr_of!(ace.SidStart).cast_mut().cast())
        } else if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            // SAFETY: this ACE type has the ACCESS_DENIED_ACE layout.
            let ace = unsafe { &*raw_ace.cast::<ACCESS_DENIED_ACE>() };
            PSID(std::ptr::addr_of!(ace.SidStart).cast_mut().cast())
        } else {
            continue;
        };

        // SAFETY: both SIDs are valid and remain alive for this comparison.
        if unsafe { EqualSid(ace_sid, sid) }.is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// The `\\?\` verbatim spelling of `path`.
///
/// The named security APIs reject object names deeper than `MAX_PATH` unless
/// they are spelled verbatim, and a granted tree can itself sit deeper than
/// that. Resolving the path first hands them the `\\?\` form they accept at
/// any depth, while the errors keep naming the path the caller asked for.
pub(crate) fn resolve(path: &Path) -> io::Result<String> {
    let resolved = std::fs::canonicalize(path).map_err(|source| {
        io::Error::other(format!("cannot resolve {}: {source}", path.display()))
    })?;
    Ok(resolved.to_string_lossy().into_owned())
}

/// Read the DACL of the object `name` refers to, retrying while it moves.
///
/// The returned pair is the security descriptor — whose `LocalBuffer` owns
/// the memory the list points into — and the list itself.
fn read_dacl(name: &str, kind: SE_OBJECT_TYPE) -> io::Result<(LocalBuffer, *mut ACL)> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let mut current: *mut ACL = std::ptr::null_mut();

    reread(name, || {
        descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        current = std::ptr::null_mut();
        // SAFETY: the path is NUL-terminated and the out-parameters are valid.
        unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                kind,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut current),
                None,
                &mut descriptor,
            )
        }
    })?;
    Ok((LocalBuffer(descriptor.0), current))
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

/// Build a copy of `current` with every entry `sddl` holds removed.
///
/// `REVOKE_ACCESS` drops the trustee's entries whatever their mask or
/// inheritance, which is what cleanup asks: the container removes exactly
/// the entries its SID carries, and entries other SIDs — other sandboxes',
/// the machine's — are not the trustee's and stay.
///
/// The returned ACL is `LocalAlloc` memory the caller frees, and `object`
/// names what is being edited for the error.
fn without(sddl: &str, current: *mut ACL, object: &str) -> io::Result<LocalBuffer> {
    let (_sid_buffer, sid) = parse_sid(sddl)?;

    let trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: PWSTR(sid.0.cast()),
        ..Default::default()
    };
    let access = [EXPLICIT_ACCESS_W {
        grfAccessPermissions: 0,
        grfAccessMode: REVOKE_ACCESS,
        grfInheritance: ACE_FLAGS(0),
        Trustee: trustee,
    }];

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
/// `name` reaches the named security APIs as given — a filesystem path
/// already spelled verbatim, or an object name such as a device or pipe —
/// and `kind` tells the APIs how to open it.
fn apply(name: &str, sddl: &str, entries: &[Entry], kind: SE_OBJECT_TYPE) -> io::Result<()> {
    let _guard = acquire()?;
    let (_descriptor, current) = read_dacl(name, kind)?;
    let updated = merge(sddl, current, entries, name)?;
    write_dacl(name, updated, kind)
}

/// Replace the DACL of the object `name` refers to with `list`.
///
/// `SetNamedSecurityInfoW` propagates inheritable entries through the tree
/// below a directory — what installs a grant's entries on the children the
/// tree already holds, and what removes them again when the entry they came
/// from is revoked.
fn write_dacl(name: &str, list: LocalBuffer, kind: SE_OBJECT_TYPE) -> io::Result<()> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: `list` is the list just built, valid until it is dropped below.
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            kind,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(list.0.cast()),
            None,
        )
    };
    drop(list);

    if status.is_err() {
        return Err(io::Error::other(format!(
            "cannot apply the access control list to {name}: {status:?}"
        )));
    }

    Ok(())
}

/// Replace the DACL of the file `name` refers to, propagating nothing.
///
/// `SetFileSecurityW` writes the object's own descriptor and leaves the tree
/// beneath it alone, which is what makes a this-object-only edit cheap: no
/// child inherits from it, so nothing below is touched. The list keeps the
/// protected and auto-inherited bits `descriptor` — the descriptor the
/// object's list was read from — carries, so how it relates to its parent is
/// unchanged. `NtSetSecurityObject` keeps `SE_DACL_AUTO_INHERITED` only when
/// `SE_DACL_AUTO_INHERIT_REQ` is requested; without that request, the object
/// stops being auto-inherited.
fn write_file_dacl(name: &str, descriptor: &LocalBuffer, list: LocalBuffer) -> io::Result<()> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let descriptor = PSECURITY_DESCRIPTOR(descriptor.0.cast());

    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor` is the descriptor just read, alive while its guard
    // lives, and the out-parameters are valid.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }.map_err(
        |source| io::Error::other(format!("cannot read the descriptor of {name}: {source}")),
    )?;

    let mut absolute = SECURITY_DESCRIPTOR::default();
    let written = PSECURITY_DESCRIPTOR((&raw mut absolute).cast());
    let mut inheritance_mask = SE_DACL_PROTECTED.0 | SE_DACL_AUTO_INHERITED.0;
    let mut inheritance_value = control & inheritance_mask;
    if control & SE_DACL_AUTO_INHERITED.0 != 0 {
        inheritance_mask |= SE_DACL_AUTO_INHERIT_REQ.0;
        inheritance_value |= SE_DACL_AUTO_INHERIT_REQ.0 | SE_DACL_AUTO_INHERITED.0;
    }
    let inheritance = SECURITY_DESCRIPTOR_CONTROL(inheritance_mask);
    let inheritance_value = SECURITY_DESCRIPTOR_CONTROL(inheritance_value);
    // SAFETY: `absolute` outlives every call below, and `list` — which it
    // points at once the list is set — outlives the write.
    let status = unsafe {
        InitializeSecurityDescriptor(written, SECURITY_DESCRIPTOR_REVISION)
            .and_then(|()| SetSecurityDescriptorDacl(written, true, Some(list.0.cast()), false))
            .and_then(|()| SetSecurityDescriptorControl(written, inheritance, inheritance_value))
            .and_then(|()| {
                SetFileSecurityW(PCWSTR(wide.as_ptr()), DACL_SECURITY_INFORMATION, written).ok()
            })
    };
    drop(list);

    status.map_err(|source| {
        io::Error::other(format!(
            "cannot apply the access control list to {name}: {source}"
        ))
    })
}

/// The DACL of the file `name` refers to, rendered as SDDL.
#[cfg(test)]
pub(crate) fn dacl_sddl(name: &str) -> io::Result<String> {
    let (descriptor, _current) = read_dacl(name, SE_FILE_OBJECT)?;

    let mut text = PWSTR::null();
    // SAFETY: `descriptor` names the descriptor just read, alive while its
    // guard lives, and `text` is a valid out-parameter.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(descriptor.0.cast()),
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
    }
    .map_err(|source| {
        io::Error::other(format!("cannot render the descriptor of {name}: {source}"))
    })?;

    // SAFETY: `text` came from the conversion call — a NUL-terminated
    // `LocalAlloc` string read once here and freed once below.
    let rendered = unsafe { text.to_string() }
        .map_err(|source| io::Error::other(format!("the descriptor of {name}: {source}")))?;
    // SAFETY: the buffer came from the conversion call, which documents
    // `LocalFree` as its deallocator, and it is freed exactly once.
    unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    Ok(rendered)
}

#[cfg(test)]
pub(crate) fn inherited_aces(sddl: &str) -> Vec<String> {
    sddl.split('(')
        .skip(1)
        .filter_map(|entry| {
            let entry = entry.split_once(')')?.0;
            let flags = entry.split(';').nth(1)?;
            flags.contains("ID").then(|| format!("({entry})"))
        })
        .collect()
}

/// Set `path`'s protected DACL from `sddl`.
///
/// The tests need the object's own trustee list to decide whether access is
/// already present; protecting the list prevents inherited entries from
/// making that result depend on the temporary directory's parent.
#[cfg(test)]
pub(crate) fn set_dacl_sddl(path: &Path, sddl: &str) -> io::Result<()> {
    let name = resolve(path)?;
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // SAFETY: `wide_sddl` is NUL-terminated and `descriptor` is a valid
    // out-parameter for the LocalAlloc-backed descriptor.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide_sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|source| io::Error::other(format!("cannot parse the DACL for {name}: {source}")))?;
    let _descriptor = LocalBuffer(descriptor.0.cast());

    // SAFETY: `wide_name` is NUL-terminated and the descriptor remains alive
    // until the file security call returns.
    unsafe {
        SetFileSecurityW(
            PCWSTR(wide_name.as_ptr()),
            DACL_SECURITY_INFORMATION,
            descriptor,
        )
    }
    .ok()
    .map_err(|source| io::Error::other(format!("cannot set the DACL for {name}: {source}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dacl(path: &Path) -> String {
        let name = resolve(path).expect("the path resolves");
        dacl_sddl(&name).expect("the DACL reads back")
    }

    // A this-object ACL write preserves the parent's auto-inherited DACL.
    #[test]
    fn this_object_writes_preserve_auto_inheritance() {
        let outer = tempfile::tempdir().expect("an outer temp directory");
        let marker = "S-1-15-3-1024-2";
        grant(
            outer.path(),
            marker,
            &[
                Entry {
                    access: FILE_TRAVERSE.0,
                    applies_to: Scope::Directories,
                },
                Entry {
                    access: FILE_TRAVERSE.0,
                    applies_to: Scope::Files,
                },
            ],
        )
        .expect("the outer directory gets inheritable entries");
        let target = outer.path().join("target");
        std::fs::create_dir(&target).expect("the target is created beneath the outer directory");

        let initial = dacl(&target);
        assert!(
            initial.starts_with("D:AI"),
            "the constructed parent did not produce an auto-inherited child: {initial}"
        );
        let inherited = inherited_aces(&initial);
        assert!(
            !inherited.is_empty(),
            "the DACL has inherited ACEs: {initial}"
        );

        let sid = "S-1-15-3-1024-1";
        let name =
            grant_this_only(&target, sid, FILE_TRAVERSE.0).expect("the traverse grant is written");
        let granted = dacl(&target);
        assert!(
            granted.starts_with("D:AI"),
            "the grant preserves auto-inheritance: {granted}"
        );
        assert_eq!(
            inherited_aces(&granted),
            inherited,
            "the grant preserves inherited ACEs: {granted}"
        );

        revoke_this_only(&name, sid).expect("the traverse grant is revoked");
        let revoked = dacl(&target);
        assert!(
            revoked.starts_with("D:AI"),
            "the revoke preserves auto-inheritance: {revoked}"
        );
        assert_eq!(
            inherited_aces(&revoked),
            inherited,
            "the revoke preserves inherited ACEs: {revoked}"
        );
    }
}
