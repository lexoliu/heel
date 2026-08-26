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

use rappct::acl::{AccessMask, ResourcePath};
use rappct::capability::{SecurityCapabilities, SecurityCapabilitiesBuilder};
use rappct::net::LoopbackExemptionGuard;
use rappct::profile::AppContainerProfile;
use rappct::sid::AppContainerSid;

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};

/// Capability that permits outbound connections.
const INTERNET_CLIENT: &str = "internetClient";

/// Traverse a directory.
///
/// Windows spells "enter this directory" and "run this file" with the same bit,
/// so it has to be granted on directories -- a container that cannot traverse
/// its own working directory cannot even be started there -- while being
/// withheld from files, which is what keeps a dropped payload from running.
const TRAVERSE: u32 = windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0;

/// Read a file, but not run it.
const FILE_READ: AccessMask = AccessMask::FILE_GENERIC_READ;

/// Read and run a file.
const FILE_READ_EXECUTE: AccessMask = AccessMask(
    AccessMask::FILE_GENERIC_READ.0 | windows::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE.0,
);

/// Read and write a file, but not run it.
const FILE_READ_WRITE: AccessMask =
    AccessMask(AccessMask::FILE_GENERIC_READ.0 | AccessMask::FILE_GENERIC_WRITE.0);

/// Enter and list a directory.
const DIR_READ: AccessMask = AccessMask(AccessMask::FILE_GENERIC_READ.0 | TRAVERSE);

/// Enter, list and write in a directory.
const DIR_READ_WRITE: AccessMask =
    AccessMask(AccessMask::FILE_GENERIC_READ.0 | AccessMask::FILE_GENERIC_WRITE.0 | TRAVERSE);

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
        self.grant(config.working_dir(), FILE_READ_WRITE, DIR_READ_WRITE)?;

        for path in config.readable_paths() {
            self.grant_ancestors(path)?;
            self.grant(path, FILE_READ, DIR_READ)?;
        }
        for path in config.writable_paths() {
            self.grant_ancestors(path)?;
            self.grant(path, FILE_READ_WRITE, DIR_READ_WRITE)?;
        }
        for path in config.executable_paths() {
            self.grant_ancestors(path)?;
            self.grant(path, FILE_READ_EXECUTE, DIR_READ)?;
        }

        if let Some(python) = config.python() {
            // A virtual environment is run from, and pip writes executables
            // into it, so it is the one place that is both.
            let (file, dir) = if python.allow_pip_install() {
                (
                    AccessMask(FILE_READ_WRITE.0 | FILE_READ_EXECUTE.0),
                    DIR_READ_WRITE,
                )
            } else {
                (FILE_READ_EXECUTE, DIR_READ)
            };
            self.grant_ancestors(python.venv().path())?;
            self.grant(python.venv().path(), file, dir)?;
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
            self.grant_exactly(ancestor, AccessMask(TRAVERSE))?;
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
        self.grant(program, FILE_READ_EXECUTE, DIR_READ)
    }

    /// Grant access to a path and, for a directory, to what it contains.
    ///
    /// A directory grant is inherited by its children, and Windows applies one
    /// mask to files and subdirectories alike, so `file` is what a directory's
    /// contents end up with.
    fn grant(&self, path: &Path, file: AccessMask, dir: AccessMask) -> Result<()> {
        if !path.is_dir() {
            return self.grant_exactly(path, file);
        }

        let target = ResourcePath::Directory(path.to_path_buf());
        rappct::acl::grant_to_package(target, self.sid(), dir).map_err(|source| {
            Error::path(
                path,
                std::io::Error::other(format!("ACL grant failed: {}", super::with_causes(&source))),
            )
        })
    }

    /// Grant access to exactly one path, with nothing inherited from it.
    fn grant_exactly(&self, path: &Path, access: AccessMask) -> Result<()> {
        // The `File` target is what carries no inheritance; it applies to a
        // directory just as well, which is what an ancestor needs.
        let target = ResourcePath::File(path.to_path_buf());
        rappct::acl::grant_to_package(target, self.sid(), access).map_err(|source| {
            Error::path(
                path,
                std::io::Error::other(format!("ACL grant failed: {}", super::with_causes(&source))),
            )
        })
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
