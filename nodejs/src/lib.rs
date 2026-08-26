//! Node.js bindings for the heel sandbox library.
//!
//! IPC is not exposed here: registering a host command means writing typed Rust
//! handlers, so it belongs to the Rust API rather than to a string-keyed
//! JavaScript surface.

#![deny(clippy::all)]
// The `#[napi]` macro generates the glue that JavaScript actually calls, and
// those generated items cannot carry doc comments of their own.
#![allow(missing_docs)]

mod child;
mod command;
mod config;
mod error;
mod policy;
mod python;
mod sandbox;
mod security;

pub use child::ChildProcessJs;
pub use command::{Command, ExitStatusJs, ProcessOutputJs, StdioConfigJs};
pub use config::{
    IsolationJs, ResourceLimitsJs, SandboxConfigJs, preset_python_data_science, preset_python_dev,
    preset_strict,
};
pub use policy::NetworkPolicyConfig;
pub use python::{PythonConfigJs, VenvConfigJs};
pub use sandbox::{Sandbox, create_sandbox};
pub use security::{
    SecurityConfigJs, security_config_interactive, security_config_permissive,
    security_config_strict,
};
