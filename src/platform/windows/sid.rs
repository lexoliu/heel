//! Security identifiers owned by heel.
//!
//! The AppContainer APIs hand out `PSID` pointers into allocations whose
//! release function differs per call — `FreeSid`, `LocalFree`, `HeapFree` —
//! so every caller that kept a pointer carried a lifetime and the wrong
//! deallocator with it. A [`Sid`] copies the bytes out at the boundary into
//! `u32`-aligned storage — a SID's sub-authorities are `u32` fields — and
//! keeps the `S-…` string beside them: the rest of the backend holds an
//! ordinary `Send`/`Sync` value, and a kernel pointer exists only inside a
//! call.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{CopySid, FreeSid, GetLengthSid, PSID};
use windows::core::PWSTR;

use super::Win32Failure;

/// A security identifier heel owns outright.
///
/// The SID structure is copied into `words` at construction — `u32` storage
/// so the `u32` sub-authorities inside it stay naturally aligned — and the
/// `S-…` form is rendered once, so every accessor is a plain read and the
/// value is `Send`/`Sync` without unsafe impls.
#[derive(Clone, Debug)]
pub(crate) struct Sid {
    /// The SID structure itself, in the layout `CopySid` writes.
    words: Vec<u32>,
    /// The `S-…` string form.
    sddl: String,
}

impl Sid {
    /// Copy the identifier `psid` names into a `Sid`, then release `psid`
    /// with `FreeSid` — the copy's outcome decides the result, but `psid` is
    /// freed either way.
    ///
    /// `psid` must be a valid SID that an API allocated for this call under a
    /// `FreeSid` contract — `CreateAppContainerProfile` is the one heel uses.
    pub(crate) fn from_owned_psid(psid: PSID) -> Result<Self, Win32Failure> {
        let copy = copy_words(psid);
        // SAFETY: `psid` was allocated for this call under a `FreeSid`
        // contract and is freed exactly once, whatever the copy did.
        unsafe { FreeSid(psid) };
        Self::from_words(copy?)
    }

    /// Build a `Sid` from `u32`-aligned words that `CopySid` or
    /// `CreateWellKnownSid` wrote; the shape makes a misaligned SID
    /// impossible to construct.
    pub(crate) fn from_words(words: Vec<u32>) -> Result<Self, Win32Failure> {
        let sddl = sddl(PSID(words.as_ptr().cast_mut().cast()))?;
        Ok(Self { words, sddl })
    }

    /// The identifier in the pointer form the security APIs take.
    ///
    /// The pointer borrows `self`, so it stays valid exactly as long as the
    /// `Sid` does — and nothing mutates one after construction.
    pub(crate) fn as_psid(&self) -> PSID {
        PSID(self.words.as_ptr().cast_mut().cast())
    }

    /// The `S-…` string form the ACL and firewall calls take.
    pub(crate) fn as_string(&self) -> &str {
        &self.sddl
    }
}

/// Copy the SID structure `psid` names into `u32`-aligned memory.
fn copy_words(psid: PSID) -> Result<Vec<u32>, Win32Failure> {
    // SAFETY: `psid` names a valid SID, which is the whole contract here.
    let length = unsafe { GetLengthSid(psid) };
    if length == 0 {
        return Err(Win32Failure::Invalid(
            "the AppContainer API returned an invalid SID".to_string(),
        ));
    }
    let mut words = vec![0u32; (length as usize).div_ceil(size_of::<u32>())];
    // SAFETY: `words` covers `length` bytes — the size `CopySid` asks for —
    // and `psid` is valid.
    unsafe { CopySid(length, PSID(words.as_mut_ptr().cast()), psid) }
        .map_err(Win32Failure::call("CopySid"))?;
    Ok(words)
}

/// Render `psid` in the `S-…` string form.
fn sddl(psid: PSID) -> Result<String, Win32Failure> {
    let mut text = PWSTR::null();
    // SAFETY: `psid` is valid and `text` is a writable out-parameter.
    unsafe { ConvertSidToStringSidW(psid, &raw mut text) }
        .map_err(Win32Failure::call("ConvertSidToStringSidW"))?;
    let text = LocalWide(text);
    // SAFETY: the buffer came from `ConvertSidToStringSidW`, which returns a
    // NUL-terminated `LocalAlloc` string valid until it is freed on drop.
    Ok(String::from_utf16_lossy(unsafe { text.0.as_wide() }))
}

/// A NUL-terminated UTF-16 `LocalAlloc` string, released on drop.
struct LocalWide(PWSTR);

impl Drop for LocalWide {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the buffer came from `ConvertSidToStringSidW`, which
            // documents `LocalFree` as its deallocator, and it is freed once.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
        }
    }
}
