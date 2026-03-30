//! Node.js bindings for heel sandbox library
//!
//! This crate provides NAPI-RS bindings to expose heel's sandboxing
//! capabilities to Node.js/TypeScript applications.

#![deny(clippy::all)]

mod child;
mod command;
mod config;
mod error;
mod ipc;
mod network;
mod python;
mod sandbox;
mod security;

// Re-export main types for NAPI
pub use child::ChildProcessJs;
pub use command::{Command, ExitStatusJs, ProcessOutputJs, StdioConfigJs};
pub use config::{SandboxConfigJs, preset_python_data_science, preset_python_dev, preset_strict};
pub use ipc::{IpcRouterJs, create_ipc_router};
pub use network::{DomainRequestJs, NetworkPolicyConfig};
pub use python::{PythonConfigJs, VenvConfigJs};
pub use sandbox::{Sandbox, create_sandbox};
pub use security::{SecurityConfigJs, security_config_permissive, security_config_strict};
