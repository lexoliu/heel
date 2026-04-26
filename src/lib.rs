//! Native Sandbox - Cross-platform native sandboxing library
//!
//! This library provides a simple API for running untrusted code in a secure sandbox.
//! It uses platform-native sandboxing mechanisms:
//! - macOS: `sandbox-exec` with SBPL profiles
//! - Linux: Landlock + Seccomp
//! - Windows: AppContainer
//!
//! # Example
//!
//! ```rust,ignore
//! use heel::Sandbox;
//!
//! async fn run_sandboxed() -> heel::Result<()> {
//!     // Create a sandbox with default configuration (network denied)
//!     let sandbox = Sandbox::new()?;
//!
//!     // Run a command in the sandbox
//!     let output = sandbox.command("echo")
//!         .arg("Hello from sandbox!")
//!         .output()
//!         .await?;
//!
//!     println!("Output: {}", String::from_utf8_lossy(&output.stdout));
//!     Ok(())
//! }
//! ```
//!
//! # Network Policies
//!
//! By default, all network access is denied. You can configure network access
//! using different policies:
//!
//! - [`DenyAll`] - Deny all network access (default)
//! - [`AllowAll`] - Allow all network access
//! - [`AllowList`] - Allow access to specific domains
//! - [`CustomPolicy`] - Custom async handler for network decisions
//!
//! # Python Support
//!
//! The library has built-in support for Python virtual environments:
//!
//! ```rust,ignore
//! use heel::{Sandbox, SandboxConfig, PythonConfig, VenvConfig};
//!
//! async fn run_python() -> heel::Result<()> {
//!     let venv_config = VenvConfig::builder()
//!         .packages(["requests", "numpy"])
//!         .build();
//!
//!     let config = SandboxConfig::builder()
//!         .python(PythonConfig::builder().venv(venv_config).build())
//!         .build()?;
//!
//!     let sandbox = Sandbox::with_config(config)?;
//!     let output = sandbox.run_python("import requests; print(requests.__version__)").await?;
//!     Ok(())
//! }
//! ```

mod command;
mod config;
mod error;
pub mod ipc;
mod network;
mod platform;
#[cfg(target_os = "macos")]
pub mod pty;
mod python;
mod sandbox;
mod security;
mod stdio;
mod workdir;

// Re-export public types
pub use command::Command;
pub use config::{
    PythonConfig, PythonConfigBuilder, ResourceLimits, ResourceLimitsBuilder, SandboxConfig,
    SandboxConfigBuilder, VenvConfig, VenvConfigBuilder, python_data_science_preset,
    python_dev_preset, strict_preset,
};
pub use error::{Error, Result};
pub use ipc::{IpcCommand, IpcError, IpcRouter};
pub use network::{
    AllowAll, AllowList, ConnectionDirection, CustomPolicy, DenyAll, DomainRequest, NetworkPolicy,
};
pub use platform::{Child, PlatformCapabilities, platform_capabilities};
pub use python::VenvManager;
/// Re-export rmp_serde for IpcCommand::apply_args implementations.
pub use rmp_serde;
pub use sandbox::Sandbox;
pub use security::{SecurityConfig, SecurityConfigBuilder};
pub use stdio::{ChildStderr, ChildStdin, ChildStdout, StdioConfig};
pub use workdir::WorkingDir;

// PTY support (macOS only for now)
#[cfg(target_os = "macos")]
pub use pty::PtyExitStatus;
