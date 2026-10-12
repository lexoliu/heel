//! Security identifiers owned by heel.
//!
//! The AppContainer APIs hand out `PSID` pointers into allocations whose
//! release function differs per call — `FreeSid`, `LocalFree`, `HeapFree` —
//! so every caller that kept a pointer carried a lifetime and the wrong
//! deallocator with it. A [`Sid`] copies the bytes out at the boundary and
//! keeps the `S-…` string beside them: the rest of the backend holds an
//! ordinary `Send`/`Sync` value, and a kernel pointer exists only inside a
//! call.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{CopySid, FreeSid, GetLengthSid, PSID};
use windows::core::PWSTR;

use crate::error::{Error, Result};

/// A security identifier heel owns outright.
///
/// The SID structure is copied into `bytes` at construction and the `S-…`
/// form is rendered once, so every accessor is a plain read and the value is
/// `Send`/`Sync` without unsafe impls.
#[derive(Clone, Debug)]
pub(crate) struct Sid {
    /// The SID structure itself, in the layout `CopySid` writes.
    bytes: Vec<u8>,
    /// The `S-…` string form.
    sddl: String,
}

impl Sid {
    /// Copy the identifier `psid` names into a `Sid`, then release `psid`
    /// with `FreeSid`.
    ///
    /// `psid` must be a valid SID that an API allocated for this call under a
    /// `FreeSid` contract — `CreateAppContainerProfile` is the one heel uses.
    pub(crate) fn from_owned_psid(psid: PSID) -> Result<Self> {
        let bytes = copy_bytes(psid)?;
        // SAFETY: `psid` was allocated for this call under a `FreeSid`
        // contract, the copy succeeded, and it is freed exactly once.
        unsafe { FreeSid(psid) };
        Self::from_bytes(bytes)
    }

    /// Build a `Sid` from bytes that `CopySid` or `CreateWellKnownSid` wrote.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let sddl = sddl(PSID(bytes.as_ptr().cast_mut().cast()))?;
        Ok(Self { bytes, sddl })
    }

    /// The identifier in the pointer form the security APIs take.
    ///
    /// The pointer borrows `self`, so it stays valid exactly as long as the
    /// `Sid` does — and nothing mutates one after construction.
    pub(crate) fn as_psid(&self) -> PSID {
        PSID(self.bytes.as_ptr().cast_mut().cast())
    }

    /// The `S-…` string form the ACL and firewall calls take.
    pub(crate) fn as_string(&self) -> &str {
        &self.sddl
    }
}

/// Copy the SID structure `psid` names into owned memory.
fn copy_bytes(psid: PSID) -> Result<Vec<u8>> {
    // SAFETY: `psid` names a valid SID, which is the whole contract here.
    let length = unsafe { GetLengthSid(psid) };
    if length == 0 {
        return Err(Error::InitFailed(
            "the AppContainer API returned an invalid SID".to_string(),
        ));
    }
    let mut bytes = vec![0u8; length as usize];
    // SAFETY: `bytes` holds exactly `length` bytes, the size `CopySid` asks
    // for, and `psid` is valid.
    unsafe { CopySid(length, PSID(bytes.as_mut_ptr().cast()), psid) }
        .map_err(|source| Error::InitFailed(format!("cannot copy the container SID: {source}")))?;
    Ok(bytes)
}

/// Render `psid` in the `S-…` string form.
fn sddl(psid: PSID) -> Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: `psid` is valid and `text` is a writable out-parameter.
    unsafe { ConvertSidToStringSidW(psid, &raw mut text) }.map_err(|source| {
        Error::InitFailed(format!(
            "cannot render the container SID as a string: {source}"
        ))
    })?;
    Ok(LocalWide(text).to_string_lossy())
}

/// A NUL-terminated UTF-16 `LocalAlloc` string, released on drop.
struct LocalWide(PWSTR);

impl LocalWide {
    /// The string's contents, without the terminator.
    fn to_string_lossy(&self) -> String {
        if self.0.is_null() {
            return String::new();
        }
        let mut length = 0;
        // SAFETY: the buffer came from `ConvertSidToStringSidW`, which returns
        // NUL-terminated `LocalAlloc` memory, so scanning to the first NUL
        // stays in bounds.
        while unsafe { *self.0.0.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: as above — `length` characters are in bounds and initialized.
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(self.0.0, length) })
    }
}

impl Drop for LocalWide {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the buffer came from `ConvertSidToStringSidW`, which
            // documents `LocalFree` as its deallocator, and it is freed once.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
        }
    }
}
