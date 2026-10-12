//! The one capability a sandbox can carry.
//!
//! Network access is a capability rather than a path: without
//! `internetClient` a container cannot open an outbound connection at all,
//! which is what a deny-all policy needs. A filtering policy adds it so the
//! proxy can be reached. The SID is a well-known identifier, so it is built
//! with `CreateWellKnownSid` rather than the name-derivation API.

use windows::Win32::Security::{
    CreateWellKnownSid, GetLengthSid, PSID, SECURITY_MAX_SID_SIZE, WinCapabilityInternetClientSid,
};

use super::Win32Failure;
use super::sid::Sid;

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
