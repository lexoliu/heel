//! Inter-process communication between sandboxed processes and the host.
//!
//! Sandboxed code cannot reach the network or the host filesystem, but it often
//! needs a narrow, audited escape hatch: a search API, a task registry, a
//! secret it must never see the value of. IPC provides exactly that. The host
//! registers typed commands; the sandbox sees them as ordinary executables on
//! its `PATH`.
//!
//! Transport is a Unix domain socket inside the sandbox working directory,
//! created with owner-only permissions. Messages are MessagePack.
//!
//! # Example
//!
//! ```rust,ignore
//! use serde::Deserialize;
//! use heel::ipc::{IpcCommand, IpcRouter};
//!
//! struct WebSearch {
//!     client: SearchClient,
//! }
//!
//! #[derive(Deserialize)]
//! struct WebSearchArgs {
//!     query: String,
//! }
//!
//! impl IpcCommand for WebSearch {
//!     const NAME: &'static str = "web_search";
//!     const POSITIONAL_ARGS: &'static [&'static str] = &["query"];
//!
//!     type Args = WebSearchArgs;
//!     type Response = Vec<String>;
//!
//!     async fn handle(&self, args: WebSearchArgs) -> Vec<String> {
//!         self.client.search(&args.query).await
//!     }
//! }
//!
//! let router = IpcRouter::new().register(WebSearch { client });
//! ```
//!
//! Inside the sandbox, `web_search "rust sandboxing"` then reaches the host
//! handler with `query` populated.

mod client;
mod command;
mod endpoint;
mod protocol;
mod router;
pub(crate) mod server;
mod wrappers;

pub use client::IpcClient;
pub use command::{IpcCommand, NoArgs};
pub use protocol::IpcError;
pub use router::{CommandMeta, IpcRouter};
pub use wrappers::{HEEL_DIR_NAME, SOCKET_NAME, WRAPPER_DIR_NAME};

// Internal to the sandbox lifecycle, not part of the public surface.
pub(crate) use server::IpcServer;
pub(crate) use wrappers::{IpcLayout, socket_root};
