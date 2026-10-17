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
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;

use windows::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL, LocalFree, WIN32_ERROR,
};
#[cfg(test)]
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    GetSecurityInfo, REVOKE_ACCESS, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
    SetEntriesInAclW, SetNamedSecurityInfoW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl,
    INHERIT_ONLY_ACE, InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED, SECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL,
    SetFileSecurityW, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING, WRITE_DAC,
};
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
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
/// `ERROR_INSUFFICIENT_BUFFER`. None of heel's writes targets another
/// sandbox's objects, but a writer outside this process cannot be ruled
/// out, so a descriptor can move under any reader — and the API's answer
/// is to ask again. The loop stays bounded so a descriptor that cannot
/// be read still fails after `ATTEMPTS` tries.
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

/// Remove every entry `sddl` holds on the object `name` refers to.
///
/// The list is re-read before it is rewritten, so entries a concurrent
/// sandbox added for its own SID since this one's grant survive — only the
/// trustee's entries are dropped from a freshly read list, and other SIDs'
/// entries stay. `SetNamedSecurityInfoW` then propagates the removal through
/// the tree the same way the grant propagated the entry.
pub(crate) fn revoke(name: &str, sddl: &str) -> io::Result<()> {
    let (_descriptor, current) = read_dacl(name, SE_FILE_OBJECT)?;
    let updated = without(sddl, current, name)?;
    write_dacl(name, updated, SE_FILE_OBJECT)
}

/// Remove every entry `sddl` holds on the file `name` refers to, touching
/// nothing beneath it — the counterpart of `grant_this_only`.
pub(crate) fn revoke_this_only(name: &str, sddl: &str) -> io::Result<()> {
    let (descriptor, current) = read_dacl(name, SE_FILE_OBJECT)?;
    let updated = without(sddl, current, name)?;
    write_file_dacl(name, &descriptor, updated)
}

/// The `\\?\` verbatim spelling of `path`.
///
/// The named security APIs reject object names deeper than `MAX_PATH` unless
/// they are spelled verbatim, and a granted tree can itself sit deeper than
/// that. Resolving the path first hands them the `\\?\` form they accept at
/// any depth, while the errors keep naming the path the caller asked for.
fn resolve(path: &Path) -> io::Result<String> {
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
/// unchanged.
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
    let inheritance = SECURITY_DESCRIPTOR_CONTROL(SE_DACL_PROTECTED.0 | SE_DACL_AUTO_INHERITED.0);
    // SAFETY: `absolute` outlives every call below, and `list` — which it
    // points at once the list is set — outlives the write.
    let status = unsafe {
        InitializeSecurityDescriptor(written, SECURITY_DESCRIPTOR_REVISION)
            .and_then(|()| SetSecurityDescriptorDacl(written, true, Some(list.0.cast()), false))
            .and_then(|()| {
                SetSecurityDescriptorControl(
                    written,
                    inheritance,
                    SECURITY_DESCRIPTOR_CONTROL(control & inheritance.0),
                )
            })
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
