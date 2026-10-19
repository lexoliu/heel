//! Capability SIDs a sandbox can carry.
//!
//! Network access is a capability rather than a path: without
//! `internetClient` a container cannot open an outbound connection at all,
//! which is what a deny-all policy needs. A filtering policy adds it so the
//! proxy can be reached. Per-sandbox capabilities are derived from their
//! names.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::{
    CreateWellKnownSid, DeriveCapabilitySidsFromName, GetLengthSid, PSID, SECURITY_MAX_SID_SIZE,
    WinCapabilityInternetClientSid,
};
use windows::core::PCWSTR;

use super::Win32Failure;
use super::sid::Sid;
use super::wide;

/// The `internetClient` capability SID, owned by the caller.
///
/// A sandbox asks for it when a proxy is running: the sandboxed process talks
/// to the proxy, and the proxy is what applies the policy.
pub(crate) fn internet_client() -> Result<Sid, Win32Failure> {
    // Every well-known SID fits in `SECURITY_MAX_SID_SIZE` bytes, kept in
    // `u32` storage so its sub-authority fields stay naturally aligned.
    let mut words = vec![0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<u32>())];
    let mut length = SECURITY_MAX_SID_SIZE;
    // SAFETY: `words` covers `length` writable bytes, which is the buffer
    // contract, and no domain SID applies to a capability SID.
    unsafe {
        CreateWellKnownSid(
            WinCapabilityInternetClientSid,
            None,
            Some(PSID(words.as_mut_ptr().cast())),
            &raw mut length,
        )
    }
    .map_err(Win32Failure::call("CreateWellKnownSid"))?;

    // The call writes the SID at the front of the buffer; `GetLengthSid`
    // names its real size in bytes.
    // SAFETY: the call just wrote a valid SID into `words`.
    let used = unsafe { GetLengthSid(PSID(words.as_ptr().cast_mut().cast())) } as usize;
    words.truncate(used.div_ceil(size_of::<u32>()));
    Sid::from_words(words)
}

/// Derive an application capability SID from its name.
pub(crate) fn derived(name: &str) -> Result<Sid, Win32Failure> {
    let wide_name = wide(name);
    let mut groups = LocalSidArray::default();
    let mut capabilities = LocalSidArray::default();
    // SAFETY: `name` is NUL-terminated and each out-parameter is valid. The
    // returned arrays and every SID use the documented `LocalFree` contract.
    unsafe {
        DeriveCapabilitySidsFromName(
            PCWSTR(wide_name.as_ptr()),
            &mut groups.entries,
            &mut groups.count,
            &mut capabilities.entries,
            &mut capabilities.count,
        )
    }
    .map_err(Win32Failure::call("DeriveCapabilitySidsFromName"))?;

    let first = capabilities.first().ok_or_else(|| {
        Win32Failure::Invalid(format!(
            "DeriveCapabilitySidsFromName returned no capability SID for {name}"
        ))
    })?;
    Sid::copy_from_psid(first)
}

#[derive(Default)]
struct LocalSidArray {
    entries: *mut PSID,
    count: u32,
}

impl LocalSidArray {
    fn first(&self) -> Option<PSID> {
        if self.entries.is_null() || self.count == 0 {
            None
        } else {
            // SAFETY: a successful derivation provides `count` valid entries.
            Some(unsafe { *self.entries })
        }
    }
}

impl Drop for LocalSidArray {
    fn drop(&mut self) {
        if self.entries.is_null() {
            return;
        }
        // SAFETY: the derivation API allocated these SIDs and the array with
        // LocalAlloc; each is released once with its documented deallocator.
        unsafe {
            for sid in std::slice::from_raw_parts(self.entries, self.count as usize) {
                if !sid.0.is_null() {
                    let _ = LocalFree(Some(HLOCAL(sid.0.cast())));
                }
            }
            let _ = LocalFree(Some(HLOCAL(self.entries.cast())));
        }
    }
}
