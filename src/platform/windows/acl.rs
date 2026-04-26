#[cfg(any(test, target_os = "windows"))]
use std::collections::{BTreeMap, HashMap};
#[cfg(any(test, target_os = "windows"))]
use std::hash::Hash;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::sync::{Mutex, MutexGuard, OnceLock};

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree, WAIT_ABANDONED, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT, WIN32_ERROR,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_W,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetLengthSid, IsValidSid, NO_INHERITANCE, PSECURITY_DESCRIPTOR,
    PSID, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
#[cfg(target_os = "windows")]
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    CreateMutexW, INFINITE, ReleaseMutex, WaitForSingleObject,
};
#[cfg(target_os = "windows")]
use windows::core::PCWSTR;

#[cfg(target_os = "windows")]
use super::paths::{RootAccess, RootGrant};
#[cfg(target_os = "windows")]
use crate::error::{Error, Result};

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug)]
struct AggregateGrantRegistry<K, R, S> {
    entries: HashMap<K, AggregateGrant<R, S>>,
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug)]
struct AggregateGrant<R, S> {
    state: S,
    request_counts: BTreeMap<R, BTreeMap<u32, usize>>,
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, PartialEq, Eq)]
enum RegistryReleaseError<E> {
    UnknownGrant,
    UnknownAccessMask,
    Reconfigure(E),
    Restore(E),
}

#[cfg(any(test, target_os = "windows"))]
impl<K, R, S> Default for AggregateGrantRegistry<K, R, S> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

#[cfg(any(test, target_os = "windows"))]
impl<K, R, S> AggregateGrantRegistry<K, R, S>
where
    K: Eq + Hash,
    R: Clone + Ord,
{
    fn acquire<E>(
        &mut self,
        key: K,
        request: R,
        access_mask: u32,
        create: impl FnOnce(&[(R, u32)]) -> std::result::Result<S, E>,
        reconfigure: impl FnOnce(&mut S, &[(R, u32)]) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        if let Some(entry) = self.entries.get_mut(&key) {
            let before = aggregate_requests(&entry.request_counts);
            let mut next_counts = entry.request_counts.clone();
            increment_request(&mut next_counts, request, access_mask);
            let after = aggregate_requests(&next_counts);
            if after != before {
                reconfigure(&mut entry.state, &after)?;
            }
            entry.request_counts = next_counts;
            return Ok(());
        }

        let mut request_counts = BTreeMap::new();
        increment_request(&mut request_counts, request, access_mask);
        let active_requests = aggregate_requests(&request_counts);
        let state = create(&active_requests)?;
        self.entries.insert(
            key,
            AggregateGrant {
                state,
                request_counts,
            },
        );
        Ok(())
    }

    fn release<E>(
        &mut self,
        key: &K,
        request: &R,
        access_mask: u32,
        reconfigure: impl FnOnce(&mut S, &[(R, u32)]) -> std::result::Result<(), E>,
        restore: impl FnOnce(&mut S) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), RegistryReleaseError<E>> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Err(RegistryReleaseError::UnknownGrant);
        };

        if !entry
            .request_counts
            .get(request)
            .and_then(|access_counts| access_counts.get(&access_mask))
            .is_some_and(|count| *count > 0)
        {
            return Err(RegistryReleaseError::UnknownAccessMask);
        }

        if active_request_count(&entry.request_counts) == 1 {
            restore(&mut entry.state).map_err(RegistryReleaseError::Restore)?;
            self.entries.remove(key);
            return Ok(());
        }

        let before = aggregate_requests(&entry.request_counts);
        let mut next_counts = entry.request_counts.clone();
        decrement_request(&mut next_counts, request, access_mask)
            .expect("known request should decrement");
        let after = aggregate_requests(&next_counts);
        if after != before {
            reconfigure(&mut entry.state, &after).map_err(RegistryReleaseError::Reconfigure)?;
        }
        entry.request_counts = next_counts;
        Ok(())
    }

    #[cfg(test)]
    fn request_count(&self, key: &K, request: &R, access_mask: u32) -> usize {
        self.entries
            .get(key)
            .and_then(|entry| entry.request_counts.get(request))
            .and_then(|access_counts| access_counts.get(&access_mask))
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(any(test, target_os = "windows"))]
fn increment_request<R: Ord>(
    counts: &mut BTreeMap<R, BTreeMap<u32, usize>>,
    request: R,
    access_mask: u32,
) {
    *counts
        .entry(request)
        .or_default()
        .entry(access_mask)
        .or_insert(0) += 1;
}

#[cfg(any(test, target_os = "windows"))]
fn decrement_request<R: Ord>(
    counts: &mut BTreeMap<R, BTreeMap<u32, usize>>,
    request: &R,
    access_mask: u32,
) -> Option<()> {
    let access_counts = counts.get_mut(request)?;
    let count = access_counts.get_mut(&access_mask)?;
    *count = count.checked_sub(1)?;
    if *count == 0 {
        access_counts.remove(&access_mask);
    }
    if access_counts.is_empty() {
        counts.remove(request);
    }
    Some(())
}

#[cfg(any(test, target_os = "windows"))]
fn aggregate_requests<R: Clone>(counts: &BTreeMap<R, BTreeMap<u32, usize>>) -> Vec<(R, u32)> {
    counts
        .iter()
        .filter_map(|(request, access_counts)| {
            let access_mask = aggregate_access_mask(access_counts);
            (access_mask != 0).then(|| (request.clone(), access_mask))
        })
        .collect()
}

#[cfg(any(test, target_os = "windows"))]
fn aggregate_access_mask(counts: &BTreeMap<u32, usize>) -> u32 {
    counts
        .iter()
        .filter_map(|(mask, count)| (*count > 0).then_some(*mask))
        .fold(0, |aggregate, mask| aggregate | mask)
}

#[cfg(any(test, target_os = "windows"))]
fn active_request_count<R>(counts: &BTreeMap<R, BTreeMap<u32, usize>>) -> usize {
    counts.values().flat_map(BTreeMap::values).copied().sum()
}

#[cfg(any(test, target_os = "windows"))]
fn global_acl_mutex_name() -> &'static str {
    "Local\\heel-acl-coordination"
}

#[cfg(target_os = "windows")]
#[must_use = "dropping AclGrantGuard may revoke filesystem access for the AppContainer"]
pub(crate) struct AclGrantGuard {
    acquisitions: Vec<GrantAcquisition>,
    _coordination_mutex: GlobalAclMutexGuard,
}

#[cfg(target_os = "windows")]
impl Drop for AclGrantGuard {
    fn drop(&mut self) {
        if let Err(error) = self.release_all() {
            tracing::warn!("failed to release Windows AppContainer ACL grants: {error}");
        }
    }
}

#[cfg(target_os = "windows")]
impl AclGrantGuard {
    fn new(coordination_mutex: GlobalAclMutexGuard) -> Self {
        Self {
            acquisitions: Vec::new(),
            _coordination_mutex: coordination_mutex,
        }
    }

    fn push(&mut self, acquisition: GrantAcquisition) {
        self.acquisitions.push(acquisition);
    }

    fn release_all(&mut self) -> Result<()> {
        while let Some(acquisition) = self.acquisitions.pop() {
            if let Err(error) = release_registered_grant(&acquisition) {
                let message = format!("{}: {error}", acquisition.display());
                self.acquisitions.push(acquisition);
                return Err(Error::FfiError(format!(
                    "failed to release Windows ACL grant: {message}"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct GrantResourceKey {
    path: PathBuf,
    inheritance: u32,
}

#[cfg(target_os = "windows")]
impl GrantResourceKey {
    fn from_grant(grant: &RootGrant) -> Result<Self> {
        let path = std::fs::canonicalize(&grant.path).map_err(|error| {
            Error::IoError(format!(
                "failed to canonicalize Windows ACL grant root '{}': {error}",
                grant.path.display()
            ))
        })?;

        Ok(Self {
            path,
            inheritance: inheritance_for(grant.is_directory).0,
        })
    }

    fn display(&self) -> String {
        format!(
            "path='{}', inheritance={}",
            self.path.display(),
            self.inheritance
        )
    }
}

#[cfg(target_os = "windows")]
#[derive(Clone, Debug)]
struct GrantAcquisition {
    resource_key: GrantResourceKey,
    sid: Vec<u8>,
    access_mask: u32,
}

#[cfg(target_os = "windows")]
impl GrantAcquisition {
    fn from_grant(grant: &RootGrant, sid: PSID) -> Result<Self> {
        Ok(Self {
            resource_key: GrantResourceKey::from_grant(grant)?,
            sid: sid_bytes(sid)?,
            access_mask: access_mask_for(grant.access),
        })
    }

    fn display(&self) -> String {
        format!(
            "{}, access={}",
            self.resource_key.display(),
            self.access_mask
        )
    }
}

#[cfg(target_os = "windows")]
struct AppliedAclGrant {
    path: PathBuf,
    path_wide: Vec<u16>,
    inheritance: u32,
    original_dacl: *mut ACL,
    _security_descriptor: LocalSecurityDescriptor,
}

#[cfg(target_os = "windows")]
impl AppliedAclGrant {
    fn apply(resource_key: &GrantResourceKey, active_requests: &[(Vec<u8>, u32)]) -> Result<Self> {
        let path_wide = wide_path(&resource_key.path)?;
        let mut original_dacl: *mut ACL = std::ptr::null_mut();
        let mut security_descriptor = PSECURITY_DESCRIPTOR::default();

        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut original_dacl),
                None,
                &mut security_descriptor,
            )
        };
        check_win32(status, "GetNamedSecurityInfoW", &resource_key.path)?;
        if security_descriptor.is_invalid() {
            return Err(Error::FfiError(format!(
                "GetNamedSecurityInfoW returned a null security descriptor for '{}'",
                resource_key.path.display()
            )));
        }

        let security_descriptor = LocalSecurityDescriptor::new(security_descriptor);
        let applied = Self {
            path: resource_key.path.clone(),
            path_wide,
            inheritance: resource_key.inheritance,
            original_dacl,
            _security_descriptor: security_descriptor,
        };
        applied.apply_access_masks(active_requests)?;

        Ok(applied)
    }

    fn reapply(&mut self, active_requests: &[(Vec<u8>, u32)]) -> Result<()> {
        self.apply_access_masks(active_requests)
    }

    fn apply_access_masks(&self, active_requests: &[(Vec<u8>, u32)]) -> Result<()> {
        if active_requests.is_empty() {
            return Err(Error::FfiError(format!(
                "cannot apply Windows ACL grant for '{}' without active SID requests",
                self.path.display()
            )));
        }

        let mut explicit_accesses = Vec::with_capacity(active_requests.len());
        for (sid, access_mask) in active_requests {
            let mut trustee = TRUSTEE_W::default();
            unsafe {
                BuildTrusteeWithSidW(&mut trustee, psid_from_bytes(sid));
            }

            explicit_accesses.push(EXPLICIT_ACCESS_W {
                grfAccessPermissions: *access_mask,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: windows::Win32::Security::ACE_FLAGS(self.inheritance),
                Trustee: trustee,
            });
        }

        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let status = unsafe {
            SetEntriesInAclW(
                Some(&explicit_accesses),
                acl_ptr_option(self.original_dacl.cast_const()),
                &mut new_dacl,
            )
        };
        check_win32(status, "SetEntriesInAclW", &self.path)?;
        if new_dacl.is_null() {
            return Err(Error::FfiError(format!(
                "SetEntriesInAclW returned a null DACL for '{}'",
                self.path.display()
            )));
        }
        let new_dacl = LocalAcl::new(new_dacl);

        let status = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(self.path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                PSID::default(),
                PSID::default(),
                Some(new_dacl.as_ptr()),
                None,
            )
        };
        check_win32(status, "SetNamedSecurityInfoW", &self.path)
    }

    fn restore(&self) -> Result<()> {
        let status = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(self.path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                PSID::default(),
                PSID::default(),
                acl_ptr_option(self.original_dacl.cast_const()),
                None,
            )
        };

        check_win32(status, "SetNamedSecurityInfoW restore", &self.path)
    }
}

#[cfg(target_os = "windows")]
unsafe impl Send for AppliedAclGrant {}

#[cfg(target_os = "windows")]
struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

#[cfg(target_os = "windows")]
impl LocalSecurityDescriptor {
    fn new(security_descriptor: PSECURITY_DESCRIPTOR) -> Self {
        Self(security_descriptor)
    }
}

#[cfg(target_os = "windows")]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        free_local(self.0.0, "security descriptor");
    }
}

#[cfg(target_os = "windows")]
struct LocalAcl(*mut ACL);

#[cfg(target_os = "windows")]
impl LocalAcl {
    fn new(acl: *mut ACL) -> Self {
        Self(acl)
    }

    fn as_ptr(&self) -> *const ACL {
        self.0.cast_const()
    }
}

#[cfg(target_os = "windows")]
impl Drop for LocalAcl {
    fn drop(&mut self) {
        free_local(self.0.cast(), "ACL");
    }
}

#[cfg(target_os = "windows")]
struct GlobalAclMutexGuard {
    release_signal: Option<std::sync::mpsc::Sender<()>>,
    owner_thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "windows")]
impl GlobalAclMutexGuard {
    fn acquire() -> Result<Self> {
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let owner_thread = std::thread::Builder::new()
            .name("heel-windows-acl-mutex".to_string())
            .spawn(move || acl_mutex_owner_thread(ready_sender, release_receiver))
            .map_err(|error| {
                Error::FfiError(format!(
                    "failed to spawn Windows ACL mutex owner thread: {error}"
                ))
            })?;

        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                release_signal: Some(release_sender),
                owner_thread: Some(owner_thread),
            }),
            Ok(Err(error)) => {
                join_acl_mutex_owner(owner_thread);
                Err(error)
            }
            Err(error) => {
                join_acl_mutex_owner(owner_thread);
                Err(Error::FfiError(format!(
                    "Windows ACL mutex owner thread exited before reporting acquisition: {error}"
                )))
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for GlobalAclMutexGuard {
    fn drop(&mut self) {
        if let Some(release_signal) = self.release_signal.take()
            && release_signal.send(()).is_err()
        {
            tracing::warn!("Windows ACL mutex owner thread stopped before release signal");
        }
        if let Some(owner_thread) = self.owner_thread.take() {
            join_acl_mutex_owner(owner_thread);
        }
    }
}

#[cfg(target_os = "windows")]
fn acl_mutex_owner_thread(
    ready_sender: std::sync::mpsc::SyncSender<Result<()>>,
    release_receiver: std::sync::mpsc::Receiver<()>,
) {
    let name = global_acl_mutex_name();
    let mutex_name = wide_mutex_name(name);
    let handle = match unsafe { CreateMutexW(None, false, PCWSTR(mutex_name.as_ptr())) } {
        Ok(handle) => handle,
        Err(error) => {
            let _ = ready_sender.send(Err(Error::FfiError(format!(
                "CreateMutexW failed for Windows ACL coordination mutex {name}: {error}"
            ))));
            return;
        }
    };

    let wait = unsafe { WaitForSingleObject(handle, INFINITE) };
    if wait == WAIT_OBJECT_0 {
        let _ = ready_sender.send(Ok(()));
        let _ = release_receiver.recv();
        release_acl_mutex(handle, name);
        return;
    }

    if wait == WAIT_ABANDONED {
        close_acl_mutex_handle(handle, name, "after abandoned wait");
        let _ = ready_sender.send(Err(Error::FfiError(format!(
            "Windows ACL coordination mutex {name} was abandoned by a previous owner; refusing to snapshot or mutate ACLs until the affected filesystem ACLs are manually inspected or explicitly recovered"
        ))));
        return;
    }

    close_acl_mutex_handle(handle, name, "after wait failure");
    if wait == WAIT_TIMEOUT {
        let _ = ready_sender.send(Err(Error::FfiError(format!(
            "WaitForSingleObject timed out for Windows ACL coordination mutex {name}"
        ))));
        return;
    }
    if wait == WAIT_FAILED {
        let _ = ready_sender.send(Err(Error::FfiError(format!(
            "WaitForSingleObject failed for Windows ACL coordination mutex {name}: {}",
            std::io::Error::last_os_error()
        ))));
        return;
    }

    let _ = ready_sender.send(Err(Error::FfiError(format!(
        "WaitForSingleObject returned unexpected status {} for Windows ACL coordination mutex {name}",
        wait.0
    ))));
}

#[cfg(target_os = "windows")]
fn release_acl_mutex(handle: HANDLE, name: &str) {
    if let Err(error) = unsafe { ReleaseMutex(handle) } {
        tracing::warn!(
            mutex = %name,
            "failed to release Windows ACL coordination mutex: {error}"
        );
    }
    close_acl_mutex_handle(handle, name, "after release");
}

#[cfg(target_os = "windows")]
fn close_acl_mutex_handle(handle: HANDLE, name: &str, context: &'static str) {
    if let Err(error) = unsafe { CloseHandle(handle) } {
        tracing::warn!(
            mutex = %name,
            "failed to close Windows ACL coordination mutex handle {context}: {error}"
        );
    }
}

#[cfg(target_os = "windows")]
fn join_acl_mutex_owner(owner_thread: std::thread::JoinHandle<()>) {
    if owner_thread.join().is_err() {
        tracing::warn!("Windows ACL mutex owner thread panicked");
    }
}

#[cfg(target_os = "windows")]
fn wide_mutex_name(name: &str) -> Vec<u16> {
    name.encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>()
}

#[cfg(target_os = "windows")]
type AclRegistry = AggregateGrantRegistry<GrantResourceKey, Vec<u8>, AppliedAclGrant>;

#[cfg(target_os = "windows")]
static ACL_GRANT_REGISTRY: OnceLock<Mutex<AclRegistry>> = OnceLock::new();

#[cfg(target_os = "windows")]
pub(crate) fn apply_grants_for_appcontainer_sid(
    grants: &[RootGrant],
    sid: PSID,
) -> Result<AclGrantGuard> {
    if sid.is_invalid() {
        return Err(Error::FfiError(
            "cannot apply Windows ACL grants for a null AppContainer SID".to_string(),
        ));
    }

    let mut acquisitions = Vec::with_capacity(grants.len());
    for grant in grants {
        let acquisition = GrantAcquisition::from_grant(grant, sid)?;
        acquisitions.push(acquisition);
    }
    acquisitions.sort_by(|left, right| {
        left.resource_key
            .cmp(&right.resource_key)
            .then_with(|| left.sid.cmp(&right.sid))
            .then_with(|| left.access_mask.cmp(&right.access_mask))
    });

    let coordination_mutex = GlobalAclMutexGuard::acquire()?;
    let mut guard = AclGrantGuard::new(coordination_mutex);
    for acquisition in acquisitions {
        match acquire_registered_grant(&acquisition) {
            Ok(()) => guard.push(acquisition),
            Err(error) => {
                return rollback_or_original_error(error, &mut guard);
            }
        }
    }

    Ok(guard)
}

#[cfg(target_os = "windows")]
fn acquire_registered_grant(acquisition: &GrantAcquisition) -> Result<()> {
    let resource_key = acquisition.resource_key.clone();
    lock_registry()?.acquire(
        resource_key.clone(),
        acquisition.sid.clone(),
        acquisition.access_mask,
        |active_requests| AppliedAclGrant::apply(&resource_key, active_requests),
        AppliedAclGrant::reapply,
    )
}

#[cfg(target_os = "windows")]
fn release_registered_grant(acquisition: &GrantAcquisition) -> Result<()> {
    lock_registry()?
        .release(
            &acquisition.resource_key,
            &acquisition.sid,
            acquisition.access_mask,
            AppliedAclGrant::reapply,
            |grant| grant.restore(),
        )
        .map_err(|error| match error {
            RegistryReleaseError::UnknownGrant => Error::FfiError(format!(
                "Windows ACL grant registry had no entry for {}",
                acquisition.display()
            )),
            RegistryReleaseError::UnknownAccessMask => Error::FfiError(format!(
                "Windows ACL grant registry had no active access mask for {}",
                acquisition.display()
            )),
            RegistryReleaseError::Reconfigure(error) => error,
            RegistryReleaseError::Restore(error) => error,
        })
}

#[cfg(target_os = "windows")]
fn lock_registry() -> Result<MutexGuard<'static, AclRegistry>> {
    ACL_GRANT_REGISTRY
        .get_or_init(|| Mutex::new(AggregateGrantRegistry::default()))
        .lock()
        .map_err(|error| Error::FfiError(format!("Windows ACL grant registry poisoned: {error}")))
}

#[cfg(target_os = "windows")]
fn rollback_or_original_error(error: Error, guard: &mut AclGrantGuard) -> Result<AclGrantGuard> {
    match guard.release_all() {
        Ok(()) => Err(error),
        Err(rollback_error) => Err(Error::FfiError(format!(
            "{error}; additionally failed to roll back prior Windows ACL grants: {rollback_error}"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn access_mask_for(access: RootAccess) -> u32 {
    match access {
        RootAccess::Read => FILE_GENERIC_READ.0,
        RootAccess::Write => FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
        RootAccess::Execute | RootAccess::Runtime => FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
        RootAccess::Full => {
            FILE_GENERIC_READ.0
                | FILE_GENERIC_WRITE.0
                | FILE_GENERIC_EXECUTE.0
                | DELETE.0
                | FILE_DELETE_CHILD.0
        }
    }
}

#[cfg(target_os = "windows")]
fn inheritance_for(is_directory: bool) -> windows::Win32::Security::ACE_FLAGS {
    if is_directory {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    }
}

#[cfg(target_os = "windows")]
fn acl_ptr_option(acl: *const ACL) -> Option<*const ACL> {
    if acl.is_null() { None } else { Some(acl) }
}

#[cfg(target_os = "windows")]
fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let encoded = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if encoded[..encoded.len().saturating_sub(1)]
        .iter()
        .any(|unit| *unit == 0)
    {
        return Err(Error::ConfigError(format!(
            "Windows ACL path contains interior NUL: {}",
            path.display()
        )));
    }
    Ok(encoded)
}

#[cfg(target_os = "windows")]
fn check_win32(status: WIN32_ERROR, operation: &'static str, path: &Path) -> Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(Error::FfiError(format!(
            "{operation} failed for '{}': {} ({})",
            path.display(),
            std::io::Error::from_raw_os_error(status.0 as i32),
            status.0
        )))
    }
}

#[cfg(target_os = "windows")]
fn free_local(ptr: *mut std::ffi::c_void, label: &'static str) {
    if ptr.is_null() {
        return;
    }

    let remaining = unsafe { LocalFree(HLOCAL(ptr)) };
    if !remaining.is_invalid() {
        tracing::warn!("LocalFree returned a non-null handle while freeing Windows {label}");
    }
}

#[cfg(target_os = "windows")]
fn sid_bytes(sid: PSID) -> Result<Vec<u8>> {
    if sid.is_invalid() || !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(Error::FfiError(
            "cannot apply Windows ACL grants for an invalid AppContainer SID".to_string(),
        ));
    }

    let len = unsafe { GetLengthSid(sid) } as usize;
    if len == 0 {
        return Err(Error::FfiError(
            "Windows AppContainer SID has zero length".to_string(),
        ));
    }

    Ok(unsafe { std::slice::from_raw_parts(sid.0.cast::<u8>(), len) }.to_vec())
}

#[cfg(target_os = "windows")]
fn psid_from_bytes(sid: &[u8]) -> PSID {
    PSID(sid.as_ptr() as *mut std::ffi::c_void)
}

#[cfg(test)]
mod registry_tests {
    use super::{AggregateGrantRegistry, RegistryReleaseError, global_acl_mutex_name};
    use std::cell::RefCell;

    #[test]
    fn read_then_full_aggregates_without_resnapshotting_or_early_restore() {
        const READ: u32 = 0b001;
        const FULL: u32 = 0b111;
        let mut registry = AggregateGrantRegistry::default();
        let events = RefCell::new(Vec::new());

        registry
            .acquire(
                "same-resource",
                "sid-a",
                READ,
                |requests| {
                    events
                        .borrow_mut()
                        .push(format!("apply:{}", format_requests(requests)));
                    Ok::<_, &'static str>("original-dacl")
                },
                |state, requests| {
                    events
                        .borrow_mut()
                        .push(format!("reapply:{state}:{}", format_requests(requests)));
                    Ok::<_, &'static str>(())
                },
            )
            .expect("read acquisition");
        registry
            .acquire(
                "same-resource",
                "sid-a",
                FULL,
                |requests| {
                    events
                        .borrow_mut()
                        .push(format!("resnapshot:{}", format_requests(requests)));
                    Ok::<_, &'static str>("stale-dacl")
                },
                |state, requests| {
                    events
                        .borrow_mut()
                        .push(format!("reapply:{state}:{}", format_requests(requests)));
                    Ok::<_, &'static str>(())
                },
            )
            .expect("full acquisition");

        registry
            .release(
                &"same-resource",
                &"sid-a",
                READ,
                |state, requests| {
                    events
                        .borrow_mut()
                        .push(format!("reapply:{state}:{}", format_requests(requests)));
                    Ok::<_, &'static str>(())
                },
                |state| {
                    events.borrow_mut().push(format!("restore:{state}"));
                    Ok::<_, &'static str>(())
                },
            )
            .expect("read release should keep full active");
        assert_eq!(
            *events.borrow(),
            vec![
                "apply:sid-a=1".to_string(),
                "reapply:original-dacl:sid-a=7".to_string()
            ]
        );

        registry
            .release(
                &"same-resource",
                &"sid-a",
                FULL,
                |state, requests| {
                    events
                        .borrow_mut()
                        .push(format!("reapply:{state}:{}", format_requests(requests)));
                    Ok::<_, &'static str>(())
                },
                |state| {
                    events.borrow_mut().push(format!("restore:{state}"));
                    Ok::<_, &'static str>(())
                },
            )
            .expect("last release should restore original");

        assert_eq!(
            *events.borrow(),
            vec![
                "apply:sid-a=1".to_string(),
                "reapply:original-dacl:sid-a=7".to_string(),
                "restore:original-dacl".to_string()
            ]
        );
    }

    #[test]
    fn cross_sid_same_resource_reconfigures_per_sid_aces_without_resnapshotting() {
        const READ: u32 = 0b001;
        const FULL: u32 = 0b111;
        let mut registry = AggregateGrantRegistry::default();
        let events = RefCell::new(Vec::new());

        registry
            .acquire(
                "same-path",
                "sid-a",
                READ,
                |requests| {
                    events
                        .borrow_mut()
                        .push(format!("apply:{}", format_requests(requests)));
                    Ok::<_, &'static str>("original-dacl")
                },
                |state, requests| {
                    events
                        .borrow_mut()
                        .push(format!("reapply:{state}:{}", format_requests(requests)));
                    Ok::<_, &'static str>(())
                },
            )
            .expect("sid-a read acquisition");
        registry
            .acquire(
                "same-path",
                "sid-b",
                FULL,
                |requests| {
                    events
                        .borrow_mut()
                        .push(format!("resnapshot:{}", format_requests(requests)));
                    Ok::<_, &'static str>("stale-dacl")
                },
                |state, requests| {
                    events
                        .borrow_mut()
                        .push(format!("reapply:{state}:{}", format_requests(requests)));
                    Ok::<_, &'static str>(())
                },
            )
            .expect("sid-b full acquisition");
        registry
            .release(
                &"same-path",
                &"sid-a",
                READ,
                |state, requests| {
                    events
                        .borrow_mut()
                        .push(format!("reapply:{state}:{}", format_requests(requests)));
                    Ok::<_, &'static str>(())
                },
                |state| {
                    events.borrow_mut().push(format!("restore:{state}"));
                    Ok::<_, &'static str>(())
                },
            )
            .expect("sid-a release should keep sid-b active");
        registry
            .release(
                &"same-path",
                &"sid-b",
                FULL,
                |state, requests| {
                    events
                        .borrow_mut()
                        .push(format!("reapply:{state}:{}", format_requests(requests)));
                    Ok::<_, &'static str>(())
                },
                |state| {
                    events.borrow_mut().push(format!("restore:{state}"));
                    Ok::<_, &'static str>(())
                },
            )
            .expect("sid-b last release should restore");

        assert_eq!(
            *events.borrow(),
            vec![
                "apply:sid-a=1".to_string(),
                "reapply:original-dacl:sid-a=1,sid-b=7".to_string(),
                "reapply:original-dacl:sid-b=7".to_string(),
                "restore:original-dacl".to_string()
            ]
        );
    }

    #[test]
    fn releasing_broader_grant_reapplies_remaining_narrower_mask() {
        const READ: u32 = 0b001;
        const FULL: u32 = 0b111;
        let mut registry = AggregateGrantRegistry::default();
        let events = RefCell::new(Vec::new());

        registry
            .acquire(
                "same-resource",
                "sid-a",
                READ,
                |_| Ok::<_, &'static str>("original-dacl"),
                |_state, _requests| Ok::<_, &'static str>(()),
            )
            .expect("read acquisition");
        registry
            .acquire(
                "same-resource",
                "sid-a",
                FULL,
                |_| Ok::<_, &'static str>("stale-dacl"),
                |_state, _requests| Ok::<_, &'static str>(()),
            )
            .expect("full acquisition");

        registry
            .release(
                &"same-resource",
                &"sid-a",
                FULL,
                |state, requests| {
                    events
                        .borrow_mut()
                        .push(format!("reapply:{state}:{}", format_requests(requests)));
                    Ok::<_, &'static str>(())
                },
                |state| {
                    events.borrow_mut().push(format!("restore:{state}"));
                    Ok::<_, &'static str>(())
                },
            )
            .expect("full release should reapply read-only aggregate");

        assert_eq!(*events.borrow(), vec!["reapply:original-dacl:sid-a=1"]);
    }

    #[test]
    fn different_paths_remain_separate_resources() {
        let mut registry = AggregateGrantRegistry::default();
        let events = RefCell::new(Vec::new());

        registry
            .acquire(
                ("read-root", "inherit"),
                "sid",
                1,
                |requests| {
                    events
                        .borrow_mut()
                        .push(format!("apply-read-root:{}", format_requests(requests)));
                    Ok::<_, &'static str>("read-root-dacl")
                },
                |_state, _requests| Ok::<_, &'static str>(()),
            )
            .expect("read-root acquisition");
        registry
            .acquire(
                ("write-root", "inherit"),
                "sid",
                1,
                |requests| {
                    events
                        .borrow_mut()
                        .push(format!("apply-write-root:{}", format_requests(requests)));
                    Ok::<_, &'static str>("write-root-dacl")
                },
                |_state, _requests| Ok::<_, &'static str>(()),
            )
            .expect("write-root acquisition");

        assert_eq!(
            *events.borrow(),
            vec!["apply-read-root:sid=1", "apply-write-root:sid=1"]
        );
    }

    #[test]
    fn release_surfaces_restore_failures() {
        let mut registry = AggregateGrantRegistry::default();
        registry
            .acquire(
                "grant",
                "sid",
                1,
                |_| Ok::<_, &'static str>("original-dacl"),
                |_state, _requests| Ok::<_, &'static str>(()),
            )
            .expect("acquisition");

        let error = registry
            .release(
                &"grant",
                &"sid",
                1,
                |_state, _requests| Ok::<_, &'static str>(()),
                |_state| Err::<(), _>("restore failed"),
            )
            .expect_err("restore failure should be returned");

        assert_eq!(error, RegistryReleaseError::Restore("restore failed"));
    }

    #[test]
    fn release_rejects_unknown_keys() {
        let mut registry = AggregateGrantRegistry::<&str, &str, &str>::default();

        let error = registry
            .release(
                &"missing",
                &"sid",
                1,
                |_state, _requests| Ok::<_, &'static str>(()),
                |_state| Ok::<_, &'static str>(()),
            )
            .expect_err("unknown key should be rejected");

        assert_eq!(error, RegistryReleaseError::UnknownGrant);
    }

    #[test]
    fn release_rejects_unknown_access_masks() {
        let mut registry = AggregateGrantRegistry::default();
        registry
            .acquire(
                "grant",
                "sid",
                1,
                |_| Ok::<_, &'static str>("original-dacl"),
                |_state, _requests| Ok::<_, &'static str>(()),
            )
            .expect("acquisition");

        let error = registry
            .release(
                &"grant",
                &"sid",
                2,
                |_state, _requests| Ok::<_, &'static str>(()),
                |_state| Ok::<_, &'static str>(()),
            )
            .expect_err("unknown access mask should be rejected");

        assert_eq!(error, RegistryReleaseError::UnknownAccessMask);
    }

    #[test]
    fn failed_release_keeps_request_retryable() {
        let mut registry = AggregateGrantRegistry::default();
        registry
            .acquire(
                "grant",
                "sid",
                1,
                |_| Ok::<_, &'static str>("original-dacl"),
                |_state, _requests| Ok::<_, &'static str>(()),
            )
            .expect("acquisition");

        let error = registry
            .release(
                &"grant",
                &"sid",
                1,
                |_state, _requests| Ok::<_, &'static str>(()),
                |_state| Err::<(), _>("transient restore failure"),
            )
            .expect_err("restore failure should be returned");

        assert_eq!(
            error,
            RegistryReleaseError::Restore("transient restore failure")
        );
        assert_eq!(registry.request_count(&"grant", &"sid", 1), 1);

        registry
            .release(
                &"grant",
                &"sid",
                1,
                |_state, _requests| Ok::<_, &'static str>(()),
                |_state| Ok::<_, &'static str>(()),
            )
            .expect("retry release should still be possible");
    }

    #[test]
    fn global_mutex_name_is_stable_and_session_local() {
        let first = global_acl_mutex_name();
        let second = global_acl_mutex_name();

        assert_eq!(first, second);
        assert_eq!(first, "Local\\heel-acl-coordination");
    }

    #[test]
    fn global_mutex_name_does_not_embed_resource_paths() {
        let name = global_acl_mutex_name();

        assert!(!name.contains("Users"));
        assert!(!name.contains("Heel\\root"));
        assert!(!name.contains(':'));
    }

    fn format_requests(requests: &[(&str, u32)]) -> String {
        requests
            .iter()
            .map(|(sid, mask)| format!("{sid}={mask}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::{access_mask_for, inheritance_for};
    use crate::platform::windows::paths::{RootAccess, RootGrant, grant};
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

    #[test]
    fn root_access_maps_to_conservative_file_masks() {
        assert_eq!(access_mask_for(RootAccess::Read), FILE_GENERIC_READ.0);
        assert_eq!(
            access_mask_for(RootAccess::Write),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0
        );
        assert_eq!(
            access_mask_for(RootAccess::Execute),
            FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0
        );
        assert_eq!(
            access_mask_for(RootAccess::Runtime),
            FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0
        );
        assert_eq!(
            access_mask_for(RootAccess::Full),
            FILE_GENERIC_READ.0
                | FILE_GENERIC_WRITE.0
                | FILE_GENERIC_EXECUTE.0
                | DELETE.0
                | FILE_DELETE_CHILD.0
        );
    }

    #[test]
    fn directory_grants_inherit_to_children() {
        assert_eq!(
            inheritance_for(true),
            windows::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT
        );
        assert_eq!(
            inheritance_for(false),
            windows::Win32::Security::NO_INHERITANCE
        );
    }

    #[test]
    fn grant_keeps_write_access_available_for_acl_mapping() {
        let item: RootGrant = grant("C:/Heel/write", RootAccess::Write, true);

        assert_eq!(
            access_mask_for(item.access),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0
        );
    }
}
