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

use std::os::windows::fs::MetadataExt;
use std::path::Path;

use rappct::capability::{SecurityCapabilities, SecurityCapabilitiesBuilder};
use rappct::net::LoopbackExemptionGuard;
use rappct::profile::AppContainerProfile;
use rappct::sid::AppContainerSid;

use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_TRAVERSE,
};

use super::acl::{self, Entry, Scope};
use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::grant::Access;

/// Capability that permits outbound connections.
const INTERNET_CLIENT: &str = "internetClient";

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
    /// `Option` only so that `Drop` can consume it; it is always `Some` before.
    profile: Option<AppContainerProfile>,
}

// SAFETY: the profile owns a SID, which is read-only kernel data after
// creation — `rappct` stores it as a raw pointer, so auto Send/Sync are lost,
// but no API mutates it and deallocation is a single Drop.
unsafe impl Send for Container {}
// SAFETY: as for Send; shared `&` access exposes only read-only operations.
unsafe impl Sync for Container {}

impl Container {
    /// Create the profile for a new sandbox.
    pub(crate) fn create() -> Result<Self> {
        let name = format!("heel-{:016x}", rand::random::<u64>());
        let profile = AppContainerProfile::ensure(&name, "heel sandbox", Some("heel sandbox"))
            .map_err(|source| {
                Error::InitFailed(format!(
                    "cannot create AppContainer profile {name}: {source}"
                ))
            })?;

        tracing::debug!(profile = %name, "created AppContainer profile");
        Ok(Self {
            profile: Some(profile),
        })
    }

    /// The package SID that ACL grants and capabilities are keyed on.
    pub(crate) fn sid(&self) -> &AppContainerSid {
        // Always `Some` until `Drop`, which is the only place it is taken.
        &self
            .profile
            .as_ref()
            .expect("the profile is present until the container is dropped")
            .sid
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
    /// derived from it the same way the server derives it.
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
            Ok(()) => tracing::debug!("opened the null device to the container"),
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
    /// is what lets the container enter it — and then the tree already
    /// beneath it is walked, because Windows inheritance is not retroactive:
    /// an inheritable entry only reaches children created after it exists.
    /// Without the walk a granted directory would open itself and nothing in
    /// it, which is not what a grant means on the other backends.
    fn grant_path(&self, path: &Path, access: Access) -> Result<()> {
        let entries = access_tree(access);
        if path.is_dir() {
            self.grant(path, &entries)?;
            // The walk starts from the resolved path: `read_dir` is under the
            // same `MAX_PATH` ceiling as the ACL calls, and children joined
            // under the verbatim `\\?\` root stay listable at any depth.
            let dir = std::fs::canonicalize(path).map_err(|source| Error::path(path, source))?;
            self.grant_existing_children(&dir, &entries)
        } else {
            self.grant(
                path,
                &[Entry {
                    access: entries[1].access,
                    applies_to: Scope::ThisOnly,
                }],
            )
        }
    }

    /// Apply a grant's entries to every child already beneath `dir`.
    ///
    /// Directories get both entries — opening them, and covering children the
    /// container creates there later — and are walked for what they already
    /// hold; files get the file entry on themselves alone.
    ///
    /// Reparse points are skipped rather than followed: setting an ACL on a
    /// junction or symlink lands the entry on its target, which would open a
    /// tree outside the grant to wherever the host could already reach.
    ///
    /// `dir` arrives resolved rather than as configured: `read_dir` cannot
    /// list a directory whose own path is deeper than `MAX_PATH`, and the
    /// children it hands back stay under the `\\?\` prefix at any depth.
    fn grant_existing_children(&self, dir: &Path, entries: &[Entry; 2]) -> Result<()> {
        for child in std::fs::read_dir(dir).map_err(|source| Error::path(dir, source))? {
            let child = child.map_err(|source| Error::path(dir, source))?;
            let path = child.path();
            let metadata = child
                .metadata()
                .map_err(|source| Error::path(path.clone(), source))?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                continue;
            }
            if metadata.is_dir() {
                self.grant(&path, entries)?;
                self.grant_existing_children(&path, entries)?;
            } else {
                self.grant(
                    &path,
                    &[Entry {
                        access: entries[1].access,
                        applies_to: Scope::ThisOnly,
                    }],
                )?;
            }
        }
        Ok(())
    }

    /// Grant traverse on every directory above `path`.
    fn grant_ancestors(&self, path: &Path) -> Result<()> {
        for ancestor in path.ancestors().skip(1) {
            // A drive root is traversable by everyone already, and its ACL is
            // not ours to change.
            if ancestor.parent().is_none() || in_system_directory(ancestor) {
                continue;
            }
            self.grant(
                ancestor,
                &[Entry {
                    access: TRAVERSE,
                    applies_to: Scope::ThisOnly,
                }],
            )?;
        }
        Ok(())
    }

    /// Open a program to this container so that it can be read and run.
    ///
    /// Programs under the system directories are skipped: Windows already
    /// grants every AppContainer read and execute on them, and their ACLs are
    /// not ours to change, so asking would fail with access denied. Anything
    /// outside them has to be granted, and failing there is a real error.
    pub(crate) fn grant_program(&self, program: &Path) -> Result<()> {
        if in_system_directory(program) {
            tracing::debug!(
                program = %program.display(),
                "program is already open to every AppContainer"
            );
            return Ok(());
        }
        self.grant(
            program,
            &[Entry {
                access: READ | EXECUTE,
                applies_to: Scope::ThisOnly,
            }],
        )
    }

    /// Add entries to a path's access control list.
    fn grant(&self, path: &Path, entries: &[Entry]) -> Result<()> {
        acl::grant(path, self.sid().as_string(), entries)
            .map_err(|source| Error::path(path, source))
    }

    /// The capabilities a process gets, given whether it may reach the network.
    ///
    /// `network` is true when a proxy is running: the sandboxed process talks to
    /// the proxy, and the proxy is what applies the policy.
    pub(crate) fn capabilities(&self, network: bool) -> Result<SecurityCapabilities> {
        let mut builder = SecurityCapabilitiesBuilder::new(self.sid());
        if network {
            builder = builder.with_named(&[INTERNET_CLIENT]);
        }
        builder.build().map_err(|source| {
            Error::InitFailed(format!(
                "cannot derive container capabilities: {}",
                super::with_causes(&source)
            ))
        })
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
    pub(crate) fn exempt_loopback(&self) -> Result<LoopbackExemptionGuard> {
        LoopbackExemptionGuard::new(self.sid()).map_err(|source| {
            Error::NotEnforced(format!(
                "cannot add the loopback exemption the network proxy needs, so the network \
                 policy would not be applied: {source}. Registering one requires administrator \
                 rights; run with them, or use the deny-all policy, which needs no proxy."
            ))
        })
    }
}

/// Whether a path lives under a directory Windows opens to every package.
///
/// Compared case-insensitively, because Windows paths are, and the case a
/// program is found under does not always match the environment variable.
fn in_system_directory(path: &Path) -> bool {
    let path = path.to_string_lossy().to_lowercase();
    ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)"]
        .iter()
        .filter_map(|variable| std::env::var(variable).ok())
        .any(|root| path.starts_with(&root.to_lowercase()))
}

impl Drop for Container {
    fn drop(&mut self) {
        let Some(profile) = self.profile.take() else {
            return;
        };
        let name = profile.name.clone();
        if let Err(error) = profile.delete() {
            tracing::warn!(profile = %name, %error, "failed to delete AppContainer profile");
        }
    }
}
