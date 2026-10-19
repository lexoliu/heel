//! The AppContainer a sandbox runs its processes in.
//!
//! An AppContainer token is default-deny against the filesystem: it can only
//! reach paths whose ACL names its package SID, plus what the machine grants to
//! every package. That is the same shape the other backends enforce, so the
//! configured paths are granted one at a time and nothing else is reachable.
//!
//! Network access is a capability rather than a path. Without `internetClient`
//! a container cannot open an outbound connection at all, which is what a
//! deny-all policy needs. A filtering policy is enforced by the proxy instead,
//! and reaching the proxy needs the loopback exemption below.

use std::io;
use std::path::Path;
use std::sync::Mutex;

use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_TRAVERSE,
};

use super::acl::{self, Entry, Scope};
use super::capability;
use super::loopback::LoopbackExemption;
use super::profile::Profile;
use super::sid::Sid;
use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::grant::Access;

/// Read a file, or list a directory.
const READ: u32 = FILE_GENERIC_READ.0;

/// Write a file, or create and remove entries in a directory.
///
/// The generic write mask alone does not deliver what `Access::WRITE`
/// promises, because Windows prices removal separately: renaming a file is a
/// delete of its old name and wants `DELETE` on the file or
/// `FILE_DELETE_CHILD` on its parent, and removing a directory wants `DELETE`
/// on it. Without them a writer that stages output and renames it into place
/// — rustc emitting `.rmeta` is the shape that hit this — meets access denied
/// inside a tree it was told is writable.
const WRITE: u32 = FILE_GENERIC_WRITE.0 | DELETE.0 | FILE_DELETE_CHILD.0;

/// Enter a directory. The same bit means "run" on a file, which is the whole
/// reason directories and files are granted separately below.
const TRAVERSE: u32 = FILE_TRAVERSE.0;

/// Run a file.
const EXECUTE: u32 = FILE_GENERIC_EXECUTE.0;

/// ALL APPLICATION PACKAGES — the SID every AppContainer token carries.
const ALL_APPLICATION_PACKAGES: &str = "S-1-15-2-1";

/// What one grant opens to the container.
///
/// Directories always carry traverse so the container can enter them, and files
/// carry execute only when the grant allows it. On NTFS "run this file" and
/// "enter this directory" are the same bit, so the two scopes are the only
/// place that distinction can be drawn: a writable tree whose grant does not
/// allow execute gives its files write without execute, which is the
/// no-exec-where-you-can-write guarantee the other backends enforce, and
/// `tests/isolation_windows.rs` asserts it.
fn access_tree(access: Access) -> [Entry; 2] {
    let mut directories = READ | TRAVERSE;
    let mut files = READ;

    if access.can_write() {
        directories |= WRITE;
        files |= WRITE;
    }
    if access.can_execute() {
        files |= EXECUTE;
    }

    [
        Entry {
            access: directories,
            applies_to: Scope::Directories,
        },
        Entry {
            access: files,
            applies_to: Scope::Files,
        },
    ]
}

/// The AppContainer profile a sandbox's processes run in.
///
/// One profile per sandbox, named after a random suffix so that concurrent
/// sandboxes never share a SID and therefore never share ACL grants.
#[derive(Debug)]
pub(crate) struct Container {
    /// The profile this sandbox's processes run in.
    profile: Profile,
    /// Every access-control list this container added entries to, in the
    /// order it added them — the grants `drop` takes back, each named the
    /// way the write named it so the removal finds the same list. Grants
    /// are recorded from `&self` methods — `grant_program` runs once per
    /// launch — so the list lives behind a mutex taken only for a push.
    granted: Mutex<Vec<Granted>>,
}

/// One access-control list the container added entries to.
#[derive(Debug)]
struct Granted {
    /// The name the write used — a verbatim path or an object name — so the
    /// removal names the same list.
    name: String,
    /// How the entries are removed again.
    removal: Removal,
}

/// How an added entry is removed again, mirroring how it was written.
#[derive(Debug)]
enum Removal {
    /// Through `SetNamedSecurityInfoW`, which propagates the removal through
    /// the tree the same way it propagated the entry.
    Tree,
    /// Through `SetFileSecurityW`, which writes the object's own descriptor
    /// and nothing beneath it — the write `grant_this_only` used to add the
    /// entry.
    ThisOnly,
}

impl Container {
    /// Create the profile for a new sandbox.
    pub(crate) fn create() -> Result<Self> {
        let name = format!("heel-{:016x}", rand::random::<u64>());
        let profile = Profile::create(&name).map_err(|source| {
            Error::InitFailed(format!(
                "cannot create AppContainer profile {name}: {}",
                super::with_causes(&source)
            ))
        })?;
        Ok(Self {
            profile,
            granted: Mutex::new(Vec::new()),
        })
    }

    /// The package SID that ACL grants and capabilities are keyed on.
    pub(crate) fn sid(&self) -> &Sid {
        self.profile.sid()
    }

    /// Open the configured paths to this container.
    ///
    /// Nothing outside these grants is reachable, so a path that cannot be
    /// granted is an error rather than a silently missing permission.
    pub(crate) fn grant_configured_paths(&self, config: &SandboxConfigData) -> Result<()> {
        // Reaching a granted directory means traversing every directory above
        // it, and the working directory sits under a user profile no container
        // can enter by default. Each ancestor gets traverse and nothing else,
        // and the grant does not inherit, so their other children stay closed.
        self.grant_ancestors(config.working_dir())?;
        self.grant_path(config.working_dir(), Access::WRITE)?;

        for grant in config.grants() {
            self.grant_ancestors(grant.path())?;
            self.grant_path(grant.path(), grant.access())?;
        }

        if let Some(python) = config.python() {
            // A virtual environment is run from, and pip writes executables into
            // it, so it is the one place that is deliberately both.
            self.grant_ancestors(python.venv().path())?;
            let access = if python.allow_pip_install() {
                Access::WRITE | Access::EXEC
            } else {
                Access::EXEC
            };
            self.grant_path(python.venv().path(), access)?;
        }

        self.grant_null_device();

        Ok(())
    }

    /// Open the sandbox's IPC endpoint to this container.
    ///
    /// On Windows the endpoint is a named pipe — a kernel object with an
    /// access control list of its own, which by default names nothing an
    /// AppContainer token carries. The filesystem grants never reach it, so
    /// the package SID has to be added on the pipe itself or every connect is
    /// denied, which is the failure a capture wrapper meets the first time it
    /// reports an artifact.
    ///
    /// `socket` is the path the endpoint was bound for; the pipe name is
    /// derived from it the same way the server derives it. The pipe is the
    /// sandbox's own — bound by its IPC server and closed with it — so its
    /// entry is not recorded for removal: it dies with the pipe.
    pub(crate) fn grant_ipc_endpoint(&self, socket: &Path) -> Result<()> {
        const PIPE_ACCESS: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0;

        acl::grant_pipe(
            &crate::ipc::pipe_name(socket),
            self.sid().as_string(),
            PIPE_ACCESS,
        )
        .map_err(|source| {
            Error::InitFailed(format!(
                "cannot open the IPC endpoint to the container: {source}"
            ))
        })
    }

    /// Open the null device to this container.
    ///
    /// A process spawned with a null stdin opens `NUL`, which resolves to the
    /// kernel device `\Device\Null`. The device's access control list names
    /// nothing an AppContainer token carries, so the open is denied inside the
    /// container — and with it every spawn `std::process::Command::output`
    /// performs, because it wires the child's stdin to `NUL`. That is the
    /// failure a build tool hits when it probes a staged wrapper: the child is
    /// denied before it starts. Granting the package SID on the device object
    /// opens it to this container and nothing else.
    ///
    /// The device belongs to the machine rather than to this sandbox, so a
    /// host without the rights to change its access control list keeps a
    /// working sandbox for everything that does not touch `NUL` — the grant
    /// is attempted and a failure is reported rather than fatal.
    fn grant_null_device(&self) {
        const NULL_DEVICE: &str = r"\\.\NUL";
        const READ_WRITE: u32 = GENERIC_READ.0 | GENERIC_WRITE.0;

        match acl::grant_object(NULL_DEVICE, self.sid().as_string(), READ_WRITE) {
            Ok(()) => {
                self.record(NULL_DEVICE.to_owned(), Removal::Tree);
                tracing::debug!("opened the null device to the container");
            }
            Err(source) => tracing::warn!(
                %source,
                "cannot open the null device to the container; children that open NUL will be denied"
            ),
        }
    }

    /// Open one configured path to this container.
    ///
    /// A file takes the file entry on itself and nothing else: the directory
    /// entry's traverse bit means "run" on a file, so handing it the
    /// directory mask would make every readable file executable. A directory
    /// takes both entries — the directory entry applies to it as well, which
    /// is what lets the container enter it.
    ///
    /// One call covers the whole tree. `SetNamedSecurityInfoW` propagates a
    /// directory's inheritable entries to every child that already exists,
    /// and children created later inherit them on creation, so the tree is
    /// written once by the system. Walking it and granting each child again
    /// re-propagated every subtree once per directory above it — a
    /// toolchain tree cost minutes per sandbox.
    fn grant_path(&self, path: &Path, access: Access) -> Result<()> {
        let entries = access_tree(access);
        // The entry that applies to `path` itself is what the access check
        // asks about: a container already holding it needs nothing written.
        let desired = if path.is_dir() {
            entries[0].access
        } else {
            entries[1].access
        };
        if self.already_open(path, desired, None)? {
            tracing::debug!(
                path = %path.display(),
                "path already grants the container its access"
            );
            return Ok(());
        }
        if path.is_dir() {
            self.grant(path, &entries, desired)
        } else {
            self.grant(
                path,
                &[Entry {
                    access: desired,
                    applies_to: Scope::ThisOnly,
                }],
                desired,
            )
        }
    }

    /// Grant traverse on every directory above `path`.
    fn grant_ancestors(&self, path: &Path) -> Result<()> {
        for ancestor in path.ancestors().skip(1) {
            // A drive root is traversable by everyone already, and its ACL
            // is not ours to change.
            if ancestor.parent().is_none() {
                continue;
            }
            if self.already_open(ancestor, TRAVERSE, None)? {
                tracing::debug!(
                    path = %ancestor.display(),
                    "ancestor already grants the container traverse"
                );
                continue;
            }
            let name = acl::grant_this_only(ancestor, self.sid().as_string(), TRAVERSE).map_err(
                |source| {
                    Error::path(
                        ancestor,
                        io::Error::other(format!(
                            "the container does not already hold traverse here: {source}"
                        )),
                    )
                },
            )?;
            self.record(name, Removal::ThisOnly);
        }
        Ok(())
    }

    /// Open a program to this container so that it can be read and run.
    ///
    /// Programs Windows already opens to every package — the system
    /// directories, whose ACLs are not ours to change — need nothing
    /// written. Anything the container does not already hold has to be
    /// granted, and failing there is a real error.
    pub(crate) fn grant_program(&self, program: &Path, capability: Option<&Sid>) -> Result<()> {
        const PROGRAM_ACCESS: u32 = READ | EXECUTE;
        if self.already_open(program, PROGRAM_ACCESS, capability)? {
            tracing::debug!(
                program = %program.display(),
                "program already grants the container read and execute"
            );
            return Ok(());
        }
        self.grant(
            program,
            &[Entry {
                access: PROGRAM_ACCESS,
                applies_to: Scope::ThisOnly,
            }],
            PROGRAM_ACCESS,
        )
    }

    /// Whether the package and the launch's capability already receive
    /// `desired` from ACEs on `path`.
    ///
    /// An AppContainer token carries its package SID, its capability SIDs and
    /// ALL APPLICATION PACKAGES, but no Everyone or Users memberships. The
    /// kernel's AppContainer access check requires an ACE for one of those
    /// token SIDs, so Everyone/Users entries do not open the path to it
    /// (Microsoft, "AppContainer isolation",
    /// learn.microsoft.com/windows/win32/secauthz/appcontainer-isolation;
    /// ALL APPLICATION PACKAGES is SID S-1-15-2-1).
    ///
    /// Configured paths and their ancestors are checked before any launch
    /// chooses whether it carries `internetClient`, so those checks cannot
    /// count a capability that is not common to every launch. A program is
    /// checked per launch and can include the capability that launch receives.
    fn already_open(&self, path: &Path, desired: u32, capability: Option<&Sid>) -> Result<bool> {
        let mut trustees = vec![self.sid().as_string(), ALL_APPLICATION_PACKAGES];
        if let Some(capability) = capability {
            trustees.push(capability.as_string());
        }
        let held =
            acl::effective_rights(path, &trustees).map_err(|source| Error::path(path, source))?;
        Ok(held & desired == desired)
    }

    /// Add entries to a path's access control list, and record the grant
    /// for `drop`. `desired` names the rights being added, so a failure —
    /// a real error, not a case to absorb — says what the container lacks.
    fn grant(&self, path: &Path, entries: &[Entry], desired: u32) -> Result<()> {
        let name = acl::grant(path, self.sid().as_string(), entries).map_err(|source| {
            Error::path(
                path,
                io::Error::other(format!(
                    "the container does not already hold {} here: {source}",
                    describe(desired)
                )),
            )
        })?;
        self.record(name, Removal::Tree);
        Ok(())
    }

    /// Remember that `name`'s access control list carries this container's
    /// entries, so `drop` removes exactly them.
    fn record(&self, name: String, removal: Removal) {
        self.granted
            .lock()
            .expect("the grants lock is held only around a push")
            .push(Granted { name, removal });
    }

    /// The capability a process gets, given whether it may reach the network.
    ///
    /// `network` is true when a proxy is running: the sandboxed process talks to
    /// the proxy, and the proxy is what applies the policy. With no proxy the
    /// process gets no capability at all — `internetClient` is the difference
    /// between outbound network and none.
    pub(crate) fn capabilities(&self, network: bool) -> Result<Option<Sid>> {
        if network {
            capability::internet_client().map(Some).map_err(|source| {
                Error::InitFailed(format!(
                    "cannot derive container capabilities: {}",
                    super::with_causes(&source)
                ))
            })
        } else {
            Ok(None)
        }
    }

    /// Let this container reach the sandbox proxy on loopback.
    ///
    /// AppContainers cannot open loopback connections without an exemption, and
    /// the proxy is a loopback listener, so every filtering policy depends on
    /// this. The exemption is machine-wide and keyed on the container SID, and
    /// the returned guard removes it again.
    ///
    /// Registering one requires administrator rights. Failing here is an error
    /// rather than a downgrade: a sandbox whose traffic cannot reach the proxy
    /// is a sandbox whose network policy is not enforced.
    pub(crate) fn exempt_loopback(&self) -> Result<LoopbackExemption> {
        LoopbackExemption::add(self.sid().clone()).map_err(|source| {
            Error::NotEnforced(format!(
                "cannot add the loopback exemption the network proxy needs, so the network \
                 policy would not be applied: {source}. Registering one requires administrator \
                 rights; run with them, or use the deny-all policy, which needs no proxy."
            ))
        })
    }
}

impl Drop for Container {
    /// Take back every entry the container added.
    ///
    /// Each list is re-read before it is rewritten and only the entries this
    /// container's own SID holds are dropped, so a concurrent sandbox's
    /// entries on the same path survive the removal. A list whose removal
    /// fails is reported and the rest are still removed. A crash before this
    /// runs leaves the entries on their lists, each naming a package SID
    /// that no longer exists.
    fn drop(&mut self) {
        let Self { profile, granted } = self;
        let sid = profile.sid().as_string();
        for granted in granted
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            let result = match granted.removal {
                Removal::Tree => acl::revoke(&granted.name, sid),
                Removal::ThisOnly => acl::revoke_this_only(&granted.name, sid),
            };
            if let Err(error) = result {
                tracing::warn!(
                    path = %granted.name,
                    %error,
                    "cannot remove the container's access control entries"
                );
            }
        }
    }
}

/// The operations `mask` grants, named for messages — "read, write and
/// traverse" and the like.
fn describe(mask: u32) -> String {
    const OPERATIONS: &[(u32, &str)] = &[
        (FILE_GENERIC_READ.0, "read"),
        (FILE_GENERIC_WRITE.0, "write"),
        (FILE_GENERIC_EXECUTE.0, "execute"),
        (FILE_TRAVERSE.0, "traverse"),
        (DELETE.0, "delete"),
        (FILE_DELETE_CHILD.0, "delete children"),
    ];
    let named = OPERATIONS
        .iter()
        .filter(|(bits, _)| mask & bits == *bits)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>();
    if named.is_empty() {
        format!("access {mask:#x}")
    } else {
        named.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DACL of `path`, rendered as SDDL.
    fn dacl(path: &Path) -> String {
        let name = std::fs::canonicalize(path).expect("the path resolves");
        acl::dacl_sddl(&name.to_string_lossy()).expect("the list reads back")
    }

    #[test]
    fn drop_removes_every_entry_the_container_added() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).expect("a nested directory");

        let sid = {
            let container = Container::create().expect("a container");
            let sid = container.sid().as_string().to_owned();

            container
                .grant_ancestors(dir.path())
                .expect("the ancestors grant");
            container
                .grant_path(dir.path(), Access::WRITE)
                .expect("the directory grants");
            container
                .grant_path(&nested, Access::READ | Access::EXEC)
                .expect("the nested directory grants");

            // The entries are in place before the drop — otherwise the
            // assertions below pass on an empty premise.
            for path in [&nested, dir.path()] {
                let list = dacl(path);
                assert!(
                    list.contains(&sid),
                    "no {sid} entry on {} before drop: {list}",
                    path.display()
                );
            }
            sid
        };

        // Neither the granted paths nor any ancestor keeps an entry for the
        // dropped container's SID.
        for path in std::iter::once(nested.as_path()).chain(dir.path().ancestors()) {
            let list = dacl(path);
            assert!(
                !list.contains(&sid),
                "an entry for {sid} remains on {}: {list}",
                path.display()
            );
        }
    }

    #[test]
    fn an_already_open_directory_is_granted_without_an_acl_write() {
        // `%SystemRoot%\System32` grants ALL APPLICATION PACKAGES read and
        // execute, so the container already holds everything a read/execute
        // grant promises: the grant must be a skip, not an ACL write. The
        // recorded grants are exactly the writes the container made, so an
        // empty list proves nothing was written — on a host with the rights
        // to write there, no less than on one without.
        let system32 =
            Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot is set")).join("System32");
        let container = Container::create().expect("a container");
        container
            .grant_path(&system32, Access::READ | Access::EXEC)
            .unwrap_or_else(|error| {
                panic!(
                    "granting read and execute on {} failed; its DACL is {}: {error}",
                    system32.display(),
                    dacl(&system32)
                )
            });
        let granted = container.granted.lock().expect("the grants lock");
        assert!(
            granted.is_empty(),
            "an already-open directory must not be written; recorded {} grants; its DACL is {}",
            granted.len(),
            dacl(&system32)
        );
    }

    #[test]
    fn a_directory_the_container_cannot_reach_is_granted_for_real() {
        // A temp directory's DACL names nothing an AppContainer token
        // carries, so the grant has to add real entries — and the record
        // shows it did.
        let dir = tempfile::tempdir().expect("a temp directory");
        let container = Container::create().expect("a container");
        container
            .grant_path(dir.path(), Access::READ)
            .unwrap_or_else(|error| {
                panic!(
                    "granting read on {} failed; its DACL is {}: {error}",
                    dir.path().display(),
                    dacl(dir.path())
                )
            });
        assert!(
            !container
                .granted
                .lock()
                .expect("the grants lock")
                .is_empty(),
            "a directory the container cannot reach must be written to its DACL"
        );
    }

    #[test]
    fn a_directory_open_only_to_everyone_is_granted_to_the_container() {
        // Everyone's ACE must not suppress a grant because AppContainer
        // tokens do not carry Everyone as a trustee.
        let dir = tempfile::tempdir().expect("a temp directory");
        acl::set_dacl_sddl(dir.path(), "D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;BA)")
            .expect("the protected DACL is set");
        let container = Container::create().expect("a container");

        container
            .grant_path(dir.path(), Access::READ)
            .expect("the directory is granted");

        assert!(
            !container
                .granted
                .lock()
                .expect("the grants lock")
                .is_empty(),
            "Everyone is not a trustee carried by an AppContainer token; its DACL is {}",
            dacl(dir.path())
        );
    }

    #[test]
    fn a_directory_open_to_all_application_packages_is_not_regranted() {
        // ALL APPLICATION PACKAGES already reaches this container, so its
        // ACE must suppress a redundant ACL write.
        let dir = tempfile::tempdir().expect("a temp directory");
        acl::set_dacl_sddl(dir.path(), "D:P(A;OICI;FA;;;AC)(A;OICI;FA;;;BA)")
            .expect("the protected DACL is set");
        let container = Container::create().expect("a container");

        container
            .grant_path(dir.path(), Access::READ | Access::EXEC)
            .expect("the directory is already open");

        assert!(
            container
                .granted
                .lock()
                .expect("the grants lock")
                .is_empty(),
            "ALL APPLICATION PACKAGES already grants read and execute; its DACL is {}",
            dacl(dir.path())
        );
    }

    #[test]
    fn a_leading_deny_keeps_the_container_from_holding_read_access() {
        // The first matching deny wins over a later allow, so the DACL walk
        // must still request a grant for read.
        let dir = tempfile::tempdir().expect("a temp directory");
        acl::set_dacl_sddl(
            dir.path(),
            "D:P(D;;FR;;;AC)(A;OICI;FA;;;AC)(A;OICI;FA;;;BA)",
        )
        .expect("the protected DACL is set");
        let container = Container::create().expect("a container");

        container
            .grant_path(dir.path(), Access::READ)
            .expect("the denied read access is granted");

        assert!(
            !container
                .granted
                .lock()
                .expect("the grants lock")
                .is_empty(),
            "the leading deny must win over the later allow; its DACL is {}",
            dacl(dir.path())
        );
    }
}
