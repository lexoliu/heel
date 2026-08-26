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

use std::path::Path;

use rappct::capability::{SecurityCapabilities, SecurityCapabilitiesBuilder};
use rappct::net::LoopbackExemptionGuard;
use rappct::profile::AppContainerProfile;
use rappct::sid::AppContainerSid;

use windows::Win32::Storage::FileSystem::{
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_TRAVERSE,
};

use super::acl::{self, Entry, Scope};
use crate::config::SandboxConfigData;
use crate::error::{Error, Result};

/// Capability that permits outbound connections.
const INTERNET_CLIENT: &str = "internetClient";

/// Read a file, or list a directory.
const READ: u32 = FILE_GENERIC_READ.0;

/// Write a file, or create entries in a directory.
const WRITE: u32 = FILE_GENERIC_WRITE.0;

/// Enter a directory. The same bit means "run" on a file, which is the whole
/// reason directories and files are granted separately below.
const TRAVERSE: u32 = FILE_TRAVERSE.0;

/// Run a file.
const EXECUTE: u32 = FILE_GENERIC_EXECUTE.0;

/// What a directory tree the sandbox may write to is granted.
///
/// Directories carry traverse so the container can enter them; files do not
/// carry execute, so nothing written there can be run. That split is the
/// no-exec-where-you-can-write guarantee the other backends enforce, and
/// `tests/isolation_windows.rs` asserts it.
fn writable_tree() -> [Entry; 2] {
    [
        Entry {
            access: READ | WRITE | TRAVERSE,
            applies_to: Scope::Directories,
        },
        Entry {
            access: READ | WRITE,
            applies_to: Scope::Files,
        },
    ]
}

/// What a directory tree the sandbox may only read is granted.
fn readable_tree() -> [Entry; 2] {
    [
        Entry {
            access: READ | TRAVERSE,
            applies_to: Scope::Directories,
        },
        Entry {
            access: READ,
            applies_to: Scope::Files,
        },
    ]
}

/// What a directory tree the sandbox may run programs from is granted.
fn executable_tree() -> [Entry; 2] {
    [
        Entry {
            access: READ | TRAVERSE,
            applies_to: Scope::Directories,
        },
        Entry {
            access: READ | EXECUTE,
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
        self.grant(config.working_dir(), &writable_tree())?;

        for path in config.readable_paths() {
            self.grant_ancestors(path)?;
            self.grant(path, &readable_tree())?;
        }
        for path in config.writable_paths() {
            self.grant_ancestors(path)?;
            self.grant(path, &writable_tree())?;
        }
        for path in config.executable_paths() {
            self.grant_ancestors(path)?;
            self.grant(path, &executable_tree())?;
        }

        if let Some(python) = config.python() {
            // A virtual environment is run from, and pip writes executables into
            // it, so it is the one place that is deliberately both.
            self.grant_ancestors(python.venv().path())?;
            if python.allow_pip_install() {
                self.grant(
                    python.venv().path(),
                    &[
                        Entry {
                            access: READ | WRITE | TRAVERSE,
                            applies_to: Scope::Directories,
                        },
                        Entry {
                            access: READ | WRITE | EXECUTE,
                            applies_to: Scope::Files,
                        },
                    ],
                )?;
            } else {
                self.grant(python.venv().path(), &executable_tree())?;
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
