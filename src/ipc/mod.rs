//! Inter-Process Communication (IPC) for sandbox
//!
//! This module provides type-safe IPC between sandboxed processes and the host.
//! Communication happens over loopback TCP using MessagePack serialization.
//!
//! # Example
//!
//! ```rust,ignore
//! use serde::{Serialize, Deserialize};
//! use heel::ipc::{IpcCommand, IpcRouter};
//!
//! #[derive(Serialize, Deserialize, Default)]
//! struct WebSearch { query: String }
//!
//! #[derive(Serialize, Deserialize)]
//! struct WebSearchResult { items: Vec<String> }
//!
//! impl IpcCommand for WebSearch {
//!     type Response = WebSearchResult;
//!
//!     fn name(&self) -> String { "web_search".to_string() }
//!
//!     async fn handle(&mut self) -> WebSearchResult {
//!         WebSearchResult { items: do_search(&self.query).await }
//!     }
//! }
//!
//! let router = IpcRouter::new()
//!     .register(WebSearch::default());
//! ```

mod command;
mod protocol;
mod router;
pub(crate) mod server;

pub use command::IpcCommand;
pub use protocol::IpcError;
pub use router::{CommandMeta, IpcRouter};

// IpcServer is internal - used by Sandbox, not exposed to users
pub(crate) use server::IpcServer;
