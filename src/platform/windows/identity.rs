//! Persistent grants associated with a named AppContainer profile.
//!
//! The profile folder contains a JSON record named [`RECORD_NAME`]. It lists
//! every grant and parent-folder traverse entry heel may have written for the
//! package SID. Each entry is recorded before its ACL write and removed only
//! after revocation finishes; a grant becomes complete only after the root's
//! `SetNamedSecurityInfoW` returns. A record therefore may over-list after a
//! crash, but cannot leave an ACL write untracked.
//!
//! A grant is already complete only when its record entry is complete, its
//! access exactly matches the declaration, and the package SID has the
//! desired rights on the root's own DACL. Otherwise tree propagation is
//! applied again in case a previous propagation stopped short. The ACL mutex
//! covers reconciliation, ACL changes, and record updates, so a concurrent
//! sandbox waits and then observes the reconciled record.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
use windows::core::HRESULT;

use super::Win32Failure;
use super::acl;
use super::container;
use super::loopback::LoopbackExemption;
use super::profile::Profile;
use crate::grant::Access;
use crate::identity::{Identity, NamedProfile};

/// JSON record of persistent grants and traverse ancestors in the profile folder.
pub(super) const RECORD_NAME: &str = "heel-persistent-grants";
/// Temporary file renamed over [`RECORD_NAME`] after each record update.
const RECORD_TEMP_NAME: &str = "heel-persistent-grants.tmp";

/// Result of reconciling one persistent grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Persisted {
    /// The grant tree was written and its completed state was recorded.
    Written,
    /// The matching record and desired rights on the root's DACL were present.
    AlreadyComplete,
}

/// Grants and ancestors heel may have written for a package SID.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Record {
    /// Persistent grant trees that may contain package-SID entries.
    pub(super) grants: Vec<RecordedGrant>,
    /// Parent folders that may contain package traverse entries.
    pub(super) ancestors: Vec<String>,
}

/// One persistent grant tree stored in the profile record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RecordedGrant {
    /// The resolved path used to identify the grant.
    pub(super) path: String,
    /// The access mode declared for the path.
    pub(super) access: Access,
    /// Whether tree propagation completed at the grant root.
    pub(super) complete: bool,
}

/// Create both named profiles and apply the persistent grants to each.
pub(crate) fn prepare(identity: &Identity) -> Result<(), Win32Failure> {
    for kind in NamedProfile::ALL {
        let profile = Profile::open_named(&identity.profile_name(kind))?;
        let _ = ensure_persistent_grants(&profile, identity)?;
    }
    Ok(())
}

/// Reconcile the declared grants and ancestors with the profile record.
pub(crate) fn ensure_persistent_grants(
    profile: &Profile,
    identity: &Identity,
) -> Result<Vec<Persisted>, Win32Failure> {
    let _guard = acl::lock().map_err(Win32Failure::io("lock persistent grants"))?;
    let record_path = profile.folder().join(RECORD_NAME);
    let mut record = read_records(&record_path)?;
    let package = profile.sid().as_string();
    let mut declared = Vec::<RecordedGrant>::new();

    for grant in identity.persistent_grants() {
        let path = acl::unredirected_name(grant.path()).map_err(Win32Failure::grant_at(
            "resolve persistent grant",
            grant.path(),
        ))?;
        if let Some(existing) = declared.iter_mut().find(|entry| entry.path == path) {
            existing.access = existing.access.union(grant.access());
        } else {
            declared.push(RecordedGrant {
                path,
                access: grant.access(),
                complete: false,
            });
        }
    }

    let mut needed_ancestors = Vec::new();
    for grant in &declared {
        for ancestor in Path::new(&grant.path).ancestors().skip(1) {
            if ancestor.parent().is_none() {
                continue;
            }
            let name = acl::unredirected_name(ancestor).map_err(Win32Failure::grant_at(
                "resolve persistent grant ancestor",
                ancestor,
            ))?;
            if !needed_ancestors.contains(&name) {
                needed_ancestors.push(name);
            }
        }
    }

    let mut index = 0;
    while index < record.grants.len() {
        let recorded = record.grants[index].clone();
        let declared_access = declared
            .iter()
            .find(|entry| entry.path == recorded.path)
            .map(|entry| entry.access);
        let narrowed =
            declared_access.is_some_and(|access| recorded.access.union(access) != access);
        if declared_access.is_none() || narrowed {
            let path = Path::new(&recorded.path);
            if path_exists(path)?
                && acl::names_trustee(&recorded.path, package).map_err(Win32Failure::io_at(
                    "check persistent grant before revoking",
                    path,
                ))?
            {
                acl::revoke(&recorded.path, package)
                    .map_err(Win32Failure::io_at("revoke persistent grant", path))?;
            }

            if let Some(access) = declared_access {
                record.grants[index].access = access;
                record.grants[index].complete = false;
                index += 1;
            } else {
                record.grants.remove(index);
            }
            write_records(&record_path, &record)?;
        } else {
            index += 1;
        }
    }

    let mut index = 0;
    while index < record.ancestors.len() {
        let ancestor = record.ancestors[index].clone();
        if !needed_ancestors.contains(&ancestor) {
            let path = Path::new(&ancestor);
            if path_exists(path)?
                && acl::names_trustee(&ancestor, package).map_err(Win32Failure::io_at(
                    "check persistent grant ancestor before revoking",
                    path,
                ))?
            {
                acl::revoke_this_only(&ancestor, package).map_err(Win32Failure::io_at(
                    "revoke persistent grant ancestor",
                    path,
                ))?;
            }
            record.ancestors.remove(index);
            write_records(&record_path, &record)?;
        } else {
            index += 1;
        }
    }

    let mut outcomes = Vec::with_capacity(declared.len());
    for grant in &declared {
        let path = Path::new(&grant.path);
        for ancestor in path.ancestors().skip(1) {
            if ancestor.parent().is_none() {
                continue;
            }
            let name = acl::unredirected_name(ancestor).map_err(Win32Failure::grant_at(
                "resolve persistent grant ancestor",
                ancestor,
            ))?;
            let ancestor_path = Path::new(&name);
            if container::persistent_ancestor_is_open(profile, ancestor_path).map_err(
                Win32Failure::io_at("check persistent grant ancestor", ancestor_path),
            )? {
                continue;
            }
            if !record.ancestors.contains(&name) {
                record.ancestors.push(name.clone());
                write_records(&record_path, &record)?;
            }
            container::grant_persistent_ancestor(profile, ancestor_path).map_err(
                Win32Failure::grant_at("grant persistent ancestor", ancestor_path),
            )?;
        }

        let desired = container::persistent_path_rights(path, grant.access);
        let held = acl::effective_rights(path, &[package])
            .map_err(Win32Failure::io_at("check persistent grant", path))?;
        let existing = record
            .grants
            .iter()
            .position(|entry| entry.path == grant.path);
        let complete = existing.is_some_and(|index| {
            let recorded = &record.grants[index];
            recorded.complete && recorded.access == grant.access && held & desired == desired
        });

        if complete {
            outcomes.push(Persisted::AlreadyComplete);
        } else {
            let index = match existing {
                Some(index) => {
                    record.grants[index].access = grant.access;
                    record.grants[index].complete = false;
                    index
                }
                None => {
                    record.grants.push(RecordedGrant {
                        path: grant.path.clone(),
                        access: grant.access,
                        complete: false,
                    });
                    record.grants.len() - 1
                }
            };
            write_records(&record_path, &record)?;
            container::grant_persistent_path(profile, path, grant.access)
                .map_err(Win32Failure::Internal)?;
            record.grants[index].complete = true;
            write_records(&record_path, &record)?;
            outcomes.push(Persisted::Written);
        }

        tracing::debug!(
            identity = identity.name(),
            path = %grant.path,
            outcome = ?outcomes.last(),
            "checked persistent grant"
        );
    }

    Ok(outcomes)
}

/// Revoke the grants listed in each profile record and remove both profiles.
///
/// Every profile is attempted; the first failure is returned afterwards.
pub(crate) fn remove(identity: &Identity) -> Result<(), Win32Failure> {
    let mut first = Ok(());
    for kind in NamedProfile::ALL {
        let removed = remove_profile(&identity.profile_name(kind), kind);
        if first.is_ok() {
            first = removed;
        }
    }
    first
}

/// Revoke the grants listed in one profile's record and delete the profile.
///
/// Only the proxied profile can hold a loopback exemption.
fn remove_profile(profile_name: &str, kind: NamedProfile) -> Result<(), Win32Failure> {
    let package = Profile::derive_sid(profile_name)?;
    let _guard = acl::lock().map_err(Win32Failure::io("lock persistent grant removal"))?;
    let folder = match Profile::folder_for_sid(&package) {
        Ok(folder) => Some(folder),
        Err(Win32Failure::Win32 {
            call: "GetAppContainerFolderPath",
            source,
        }) if source.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0)
            || source.code() == HRESULT::from_win32(ERROR_PATH_NOT_FOUND.0) =>
        {
            None
        }
        Err(source) => return Err(source),
    };

    if let Some(folder) = folder {
        let record_path = folder.join(RECORD_NAME);
        let mut record = read_records(&record_path)?;
        while let Some(grant) = record.grants.pop() {
            let path = Path::new(&grant.path);
            if path_exists(path)?
                && acl::names_trustee(&grant.path, package.as_string()).map_err(
                    Win32Failure::io_at("check persistent grant before revoking", path),
                )?
            {
                acl::revoke(&grant.path, package.as_string())
                    .map_err(Win32Failure::io_at("revoke persistent grant", path))?;
            }
            write_records(&record_path, &record)?;
        }

        while let Some(ancestor) = record.ancestors.pop() {
            let path = Path::new(&ancestor);
            if path_exists(path)?
                && acl::names_trustee(&ancestor, package.as_string()).map_err(
                    Win32Failure::io_at("check persistent grant ancestor before revoking", path),
                )?
            {
                acl::revoke_this_only(&ancestor, package.as_string()).map_err(
                    Win32Failure::io_at("revoke persistent grant ancestor", path),
                )?;
            }
            write_records(&record_path, &record)?;
        }
    }

    if kind == NamedProfile::Proxied {
        LoopbackExemption::remove_persistent(&package)
            .map_err(Win32Failure::io("remove persistent loopback exemption"))?;
    }
    Profile::delete_named(profile_name)?;
    Ok(())
}

/// Read the JSON record, treating a missing file as an empty record.
pub(super) fn read_records(path: &Path) -> Result<Record, Win32Failure> {
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Record::default()),
        Err(source) => {
            return Err(Win32Failure::io_at("read persistent grant record", path)(
                source,
            ));
        }
    };

    serde_json::from_slice(&contents).map_err(|source| {
        Win32Failure::io_at("parse persistent grant record", path)(io::Error::other(source))
    })
}

/// Write the JSON record to a temporary file and rename it over the current one.
fn write_records(path: &Path, record: &Record) -> Result<(), Win32Failure> {
    let temporary = path.with_file_name(RECORD_TEMP_NAME);
    let contents = serde_json::to_vec_pretty(record).map_err(|source| {
        Win32Failure::io_at("serialize persistent grant record", path)(io::Error::other(source))
    })?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .map_err(Win32Failure::io_at(
            "open temporary persistent grant record",
            &temporary,
        ))?;
    file.write_all(&contents).map_err(Win32Failure::io_at(
        "write persistent grant record",
        &temporary,
    ))?;
    file.flush().map_err(Win32Failure::io_at(
        "flush persistent grant record",
        &temporary,
    ))?;
    drop(file);
    fs::rename(&temporary, path)
        .map_err(Win32Failure::io_at("replace persistent grant record", path))
}

/// Whether filesystem metadata can be read for `path`.
fn path_exists(path: &Path) -> Result<bool, Win32Failure> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(Win32Failure::io_at("inspect persistent grant path", path)(
            source,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_record_round_trips() {
        let directory = crate::platform::unresolved::resolved_tempdir();
        let path = directory.path().join(RECORD_NAME);
        let record = Record {
            grants: vec![RecordedGrant {
                path: r"\\?\C:\toolchain".to_owned(),
                access: Access::WRITE | Access::EXEC,
                complete: true,
            }],
            ancestors: vec![r"\\?\C:\parent".to_owned()],
        };

        write_records(&path, &record).expect("the record is written");
        let restored = read_records(&path).expect("the record is read");

        assert_eq!(restored.grants.len(), 1);
        assert_eq!(restored.grants[0].path, record.grants[0].path);
        assert_eq!(restored.grants[0].access, record.grants[0].access);
        assert!(restored.grants[0].complete);
        assert_eq!(restored.ancestors, record.ancestors);
        assert!(
            fs::read_to_string(&path)
                .expect("the JSON record is readable")
                .contains("\"rwx\"")
        );
    }

    #[test]
    fn malformed_json_record_names_its_file() {
        let directory = crate::platform::unresolved::resolved_tempdir();
        let path = directory.path().join(RECORD_NAME);
        fs::write(&path, b"{").expect("the malformed record is written");

        let error = read_records(&path).expect_err("malformed JSON is rejected");

        let message = std::error::Error::source(&error)
            .expect("the I/O failure retains its parse error")
            .to_string();
        assert!(
            message.contains(path.display().to_string().as_str()),
            "the error does not name {}: {message}",
            path.display()
        );
    }
}
