//! One AppContainer profile, created for a sandbox and removed with it.
//!
//! A profile is what turns a process token into an AppContainer token; the
//! package SID it derives from the profile name is what ACL grants, the
//! firewall's loopback exemption and a launch's security capabilities are all
//! keyed on. The SID is copied out of the creation call's allocation, so the
//! profile is a `Send`/`Sync` value like everything else the sandbox owns.

use windows::Win32::Security::Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile};
use windows::core::PCWSTR;

use super::sid::Sid;
use super::{Win32Failure, wide};

/// The AppContainer profile a sandbox's processes run in.
///
/// One profile per sandbox, named after a random suffix so that concurrent
/// sandboxes never share a SID and therefore never share ACL grants.
#[derive(Debug)]
pub(crate) struct Profile {
    /// The profile's name, which `DeleteAppContainerProfile` wants back.
    name: String,
    /// The package SID that ACL grants and capabilities are keyed on.
    sid: Sid,
}

impl Profile {
    /// Create the profile for a new sandbox, under `name`.
    ///
    /// Any failure — including an already-existing profile, which a random
    /// name makes a bug rather than a case — is reported with the error
    /// `CreateAppContainerProfile` returned.
    pub(crate) fn create(name: &str) -> Result<Self, Win32Failure> {
        let name_wide = wide(name);
        let display = wide("heel sandbox");
        let description = wide("heel sandbox");

        // SAFETY: every string is NUL-terminated and outlives the call. The
        // returned PSID is allocated for the caller under a `FreeSid`
        // contract; `Sid::from_owned_psid` copies it and releases it.
        let sid = unsafe {
            CreateAppContainerProfile(
                PCWSTR(name_wide.as_ptr()),
                PCWSTR(display.as_ptr()),
                PCWSTR(description.as_ptr()),
                None,
            )
        }
        .map_err(Win32Failure::call("CreateAppContainerProfile"))?;

        let sid = Sid::from_owned_psid(sid)?;
        tracing::debug!(profile = %name, sid = %sid.as_string(), "created AppContainer profile");
        Ok(Self {
            name: name.to_owned(),
            sid,
        })
    }

    /// The package SID that ACL grants and capabilities are keyed on.
    pub(crate) fn sid(&self) -> &Sid {
        &self.sid
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        let name = wide(&self.name);
        // SAFETY: `name` is NUL-terminated and outlives the call.
        if let Err(error) = unsafe { DeleteAppContainerProfile(PCWSTR(name.as_ptr())) } {
            tracing::warn!(profile = %self.name, %error, "failed to delete AppContainer profile");
        }
    }
}
