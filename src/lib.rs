//! Run untrusted code in a sandbox built from native OS isolation.
//!
//! `heel` wraps the isolation primitives each platform already provides:
//!
//! - **macOS**: `sandbox-exec` with generated SBPL profiles
//! - **Linux**: Landlock (ABI v4) for the filesystem and network, Seccomp for
//!   syscalls
//! - **Windows**: AppContainer + job objects (implemented, Windows 10+)
//!
//! # Example
//!
//! ```rust,ignore
//! use heel::Sandbox;
//!
//! async fn run_sandboxed() -> heel::Result<()> {
//!     // Network access is denied by default.
//!     let sandbox = Sandbox::new().await?;
//!
//!     let output = sandbox.command("echo")
//!         .arg("Hello from the sandbox")
//!         .output()
//!         .await?;
//!
//!     assert!(output.status.success());
//!     Ok(())
//! }
//! ```
//!
//! # Network policies
//!
//! A sandbox is generic over its [`NetworkPolicy`]. Under the default
//! [`DenyAll`] no proxy runs at all and the kernel denies outbound traffic; any
//! other policy starts a local proxy that every connection passes through.
//!
//! - [`DenyAll`] - deny everything (default)
//! - [`AllowAll`] - allow everything
//! - [`AllowList`] - allow specific domains, with `*.example.com` wildcards
//! - [`CustomPolicy`] - decide per request with an async handler
//! - [`Audited`] - wrap any policy to record its decisions
//!
//! # Filesystem
//!
//! Sandboxed processes may always read and write their working directory. On
//! Unix it is also exported as `TMPDIR`; on Windows the backend sets `TEMP`,
//! `TMP` and `TMPDIR` to the container's own temporary folder. Everything else
//! is opt-in through
//! [`SandboxConfigBuilder::grant`], which pairs a path with the [`Access`] the
//! sandbox has to it, and no location a process can write to may be executed.
//! An [`Access::EXEC`] grant is the deliberate exception: it may name a single
//! file or a directory whose whole tree becomes executable, so granting it on a
//! writable path gives up write-then-execute for that path.
//!
//! A granted path is a [`ResolvedPath`]: absolute, already resolved and free of
//! `.` and `..` components. The sandbox checks each of its components without following
//! symbolic links and refuses to build if one has become a link, so a grant can
//! never move to a link's target. [`resolve_paths`] turns the paths a user wrote
//! into such paths, once, and refuses a link a sandbox could have planted.
//!
//! ```rust,ignore
//! use heel::{Access, ResolvedPath, SandboxConfig};
//!
//! let config = SandboxConfig::builder()
//!     .readable(ResolvedPath::new("/usr/share")?)
//!     .grant(ResolvedPath::new(std::fs::canonicalize("target")?)?, Access::WRITE | Access::EXEC)
//!     .build();
//! ```
//!
//! # Stable identities
//!
//! A named identity can retain access to a toolchain directory across Windows
//! sandboxes. Prepare it while installing the toolchain; on macOS and Linux,
//! persistent grants are ordinary policy grants for each sandbox.
//!
//! ```rust,ignore
//! use heel::{Access, Grant, Identity, SandboxConfig};
//!
//! let identity = Identity::named("toolchain")?
//!     .persistent_grant(Grant::new("/opt/rust", Access::READ));
//!
//! // Run while installing the toolchain.
//! identity.prepare()?;
//!
//! let config = SandboxConfig::builder().identity(identity).build();
//! ```
//!
//! # Python
//!
//! ```rust,ignore
//! use heel::{PythonConfig, Sandbox, SandboxConfig, VenvConfig};
//!
//! async fn run_python() -> heel::Result<()> {
//!     let config = SandboxConfig::builder()
//!         .python(
//!             PythonConfig::builder()
//!                 .venv(VenvConfig::builder().packages(["requests"]).build())
//!                 .build(),
//!         )
//!         .build();
//!
//!     let sandbox = Sandbox::with_config(config).await?;
//!     sandbox.run_python("import requests; print(requests.__version__)").await?;
//!     Ok(())
//! }
//! ```

// Tests assert on known-good values, where an unwrap failure is the assertion.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub(crate) mod accept;
mod command;
mod config;
mod denial;
mod error;
mod grant;
mod identity;
pub mod ipc;
mod network;
mod platform;
mod policy;
mod priority;
#[cfg(target_os = "macos")]
pub(crate) mod pty;
mod python;
mod resolve;
mod sandbox;
mod security;
#[cfg(target_os = "linux")]
pub mod supervisor;
mod workdir;

#[cfg(unix)]
pub use command::DEFAULT_SANDBOX_PATH;
pub use command::{Command, StdioConfig, default_sandbox_path};
pub use config::{
    InodePool, IpcConfigured, IpcUnconfigured, PythonConfig, PythonConfigBuilder, ResourceLimits,
    ResourceLimitsBuilder, SandboxConfig, SandboxConfigBuilder, SandboxConfigData, VenvBackend,
    VenvConfig, VenvConfigBuilder, python_data_science_preset, python_dev_preset, strict_preset,
};
pub use denial::{Denial, DenialRecorder};
pub use error::{Error, Redirection, Result};
pub use grant::{Access, Grant, ParseAccessError};
pub use identity::Identity;
pub use ipc::{CommandMeta, IpcClient, IpcCommand, IpcError, IpcRouter, NoArgs};
pub use network::{
    AllowAll, AllowList, Audited, CustomPolicy, DenyAll, DomainRequest, NetworkAuditLog,
    NetworkPolicy,
};
pub use platform::Child;
pub use policy::{ReadDenylist, WriteDenylist};
pub use priority::{CpuPriority, InvalidNiceLevel, IoPriority, NiceLevel, ProcessPriority};
pub use python::VenvManager;
pub use resolve::{PathRequest, ResolvedPath, resolve_paths};
pub use sandbox::Sandbox;
pub use security::{SecurityConfig, SecurityConfigBuilder, SecurityOverrides};
pub use workdir::WorkingDir;
