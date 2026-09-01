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
//! Sandboxed processes may always read and write their working directory, which
//! is also exported as `TMPDIR`. Everything else is opt-in through
//! [`SandboxConfigBuilder::readable_path`], [`writable_path`] and
//! [`executable_path`], and no location a process can write to may be executed.
//! [`executable_path`] is the deliberate exception: it may name a single file
//! or a directory whose whole tree becomes executable, so granting it to a
//! writable directory gives up write-then-execute for that directory.
//!
//! [`writable_path`]: SandboxConfigBuilder::writable_path
//! [`executable_path`]: SandboxConfigBuilder::executable_path
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
mod error;
pub mod ipc;
mod network;
mod platform;
#[cfg(target_os = "macos")]
pub(crate) mod pty;
mod python;
mod sandbox;
mod security;
mod workdir;

pub use command::{Command, DEFAULT_SANDBOX_PATH, StdioConfig};
pub use config::{
    PythonConfig, PythonConfigBuilder, ResourceLimits, ResourceLimitsBuilder, SandboxConfig,
    SandboxConfigBuilder, SandboxConfigData, VenvBackend, VenvConfig, VenvConfigBuilder,
    python_data_science_preset, python_dev_preset, strict_preset,
};
pub use error::{Error, Result};
pub use ipc::{CommandMeta, IpcClient, IpcCommand, IpcError, IpcRouter, NoArgs};
pub use network::{
    AllowAll, AllowList, Audited, CustomPolicy, DenyAll, DomainRequest, NetworkAuditLog,
    NetworkPolicy,
};
pub use platform::Child;
pub use python::VenvManager;
pub use sandbox::Sandbox;
pub use security::{SecurityConfig, SecurityConfigBuilder, SecurityOverrides};
pub use workdir::WorkingDir;
