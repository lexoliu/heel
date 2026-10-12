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

use super::sid::Sid;
use crate::error::{Error, Result};

/// The `internetClient` capability SID, owned by the caller.
///
/// A sandbox asks for it when a proxy is running: the sandboxed process talks
/// to the proxy, and the proxy is what applies the policy.
pub(crate) fn internet_client() -> Result<Sid> {
    // Every well-known SID fits in `SECURITY_MAX_SID_SIZE` bytes.
    let mut bytes = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut length = SECURITY_MAX_SID_SIZE;
    // SAFETY: `bytes` holds `length` writable bytes, which is the buffer
    // contract, and no domain SID applies to a capability SID.
    unsafe {
        CreateWellKnownSid(
            WinCapabilityInternetClientSid,
            None,
            Some(PSID(bytes.as_mut_ptr().cast())),
            &raw mut length,
        )
    }
    .map_err(|source| {
        Error::InitFailed(format!(
            "CreateWellKnownSid(internetClient) failed: {source}"
        ))
    })?;

    // The call writes the SID at the front of the buffer; `GetLengthSid`
    // names its real size.
    // SAFETY: the call just wrote a valid SID into `bytes`.
    let used = unsafe { GetLengthSid(PSID(bytes.as_ptr().cast_mut().cast())) } as usize;
    bytes.truncate(used);
    Sid::from_bytes(bytes)
}
