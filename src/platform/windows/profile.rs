//! One AppContainer profile, created for a sandbox and removed with it.
//!
//! A profile is what turns a process token into an AppContainer token; the
//! package SID it derives from the profile name is what ACL grants, the
//! firewall's loopback exemption and a launch's security capabilities are all
//! keyed on. The SID is copied out of the creation call's allocation, so the
//! profile is a `Send`/`Sync` value like everything else the sandbox owns.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, GetAppContainerFolderPath,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::core::{PCWSTR, PWSTR};

use super::sid::Sid;
use super::{Win32Failure, wide};

/// The AppContainer profile a sandbox's processes run in.
///
/// One profile per sandbox, named after a random suffix so that concurrent
/// sandboxes never share a SID and therefore never share ACL grants.
#[derive(Debug)]
pub(crate) struct Profile {
    /// Owns the system registration and deletes it when this profile is dropped.
    _registration: Registration,
    /// The package SID that ACL grants and capabilities are keyed on.
    sid: Sid,
    /// The `GetAppContainerFolderPath` folder for this package SID. Windows
    /// appends `Packages\<profile>\AC` to the launch block's `LOCALAPPDATA`;
    /// this folder's `Temp` child is created with the profile and supplied as
    /// the child's temporary directory.
    folder: PathBuf,
    /// The base path Windows uses before appending the profile suffix.
    local_app_data: PathBuf,
}

impl Profile {
    /// Create the profile for a new sandbox, under `name`.
    ///
    /// Any failure — including an already-existing profile, which a random
    /// name makes a bug rather than a case — is reported with the call or
    /// path operation that failed.
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

        let registration = Registration {
            name: name.to_owned(),
        };
        let sid = Sid::from_owned_psid(sid)?;
        let sid_wide = wide(sid.as_string());
        // SAFETY: `sid_wide` is NUL-terminated and the profile SID remains
        // valid for the call that resolves its package folder.
        let folder = unsafe { GetAppContainerFolderPath(PCWSTR(sid_wide.as_ptr())) }
            .map_err(Win32Failure::call("GetAppContainerFolderPath"))?;
        let folder = TaskWide(folder);
        // SAFETY: `folder` is the NUL-terminated path returned by
        // `GetAppContainerFolderPath` and remains alive through conversion.
        let folder = PathBuf::from(OsString::from_wide(unsafe { folder.0.as_wide() }));
        let local_app_data = local_app_data(&folder, name)?;
        let temp = folder.join("Temp");
        std::fs::create_dir(&temp)
            .or_else(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists && temp.is_dir() {
                    Ok(())
                } else {
                    Err(source)
                }
            })
            .map_err(Win32Failure::io("create AppContainer Temp directory"))?;
        tracing::debug!(
            profile = %name,
            sid = %sid.as_string(),
            folder = %folder.display(),
            "created AppContainer profile"
        );
        Ok(Self {
            _registration: registration,
            sid,
            folder,
            local_app_data,
        })
    }

    /// The package SID that ACL grants and capabilities are keyed on.
    pub(crate) fn sid(&self) -> &Sid {
        &self.sid
    }

    /// The folder `GetAppContainerFolderPath` reports for this package SID.
    pub(crate) fn folder(&self) -> &Path {
        &self.folder
    }

    /// The base Windows appends the profile suffix to for child `LOCALAPPDATA`.
    pub(crate) fn local_app_data(&self) -> &Path {
        &self.local_app_data
    }
}

/// Owns an AppContainer registration and deletes it when dropped.
#[derive(Debug)]
struct Registration {
    name: String,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let name = wide(&self.name);
        // SAFETY: `name` is NUL-terminated and outlives the call.
        if let Err(error) = unsafe { DeleteAppContainerProfile(PCWSTR(name.as_ptr())) } {
            tracing::warn!(profile = %self.name, %error, "failed to delete AppContainer profile");
        }
    }
}

/// Strip and validate the profile suffix Windows appends to child `LOCALAPPDATA`.
fn local_app_data(folder: &Path, profile_name: &str) -> Result<PathBuf, Win32Failure> {
    let Some(profile_folder) = folder.parent() else {
        return Err(unexpected_folder(folder, profile_name));
    };
    let Some(packages_folder) = profile_folder.parent() else {
        return Err(unexpected_folder(folder, profile_name));
    };
    let Some(base) = packages_folder.parent() else {
        return Err(unexpected_folder(folder, profile_name));
    };
    let valid_suffix = component_is(folder, "AC")
        && component_is(profile_folder, profile_name)
        && component_is(packages_folder, "Packages");
    if !valid_suffix {
        return Err(unexpected_folder(folder, profile_name));
    }
    Ok(base.to_path_buf())
}

/// Whether the final path component matches `expected`, ignoring case.
fn component_is(path: &Path, expected: &str) -> bool {
    path.file_name()
        .is_some_and(|component| component.to_string_lossy().eq_ignore_ascii_case(expected))
}

/// Report a profile folder whose suffix does not match the expected layout.
fn unexpected_folder(folder: &Path, profile_name: &str) -> Win32Failure {
    Win32Failure::Invalid(format!(
        "GetAppContainerFolderPath returned unexpected folder {} for profile {profile_name}",
        folder.display()
    ))
}

/// A `CoTaskMem` string returned by `GetAppContainerFolderPath`.
struct TaskWide(PWSTR);

impl Drop for TaskWide {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `GetAppContainerFolderPath` allocates this string for
            // the caller with the `CoTaskMemFree` deallocation contract.
            unsafe { CoTaskMemFree(Some(self.0.0.cast())) };
        }
    }
}
