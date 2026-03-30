//! IPC command trait definition

use std::borrow::Cow;
use std::future::Future;

use serde::{Serialize, de::DeserializeOwned};

/// A type-safe IPC command with its handler
///
/// Users implement this trait to define commands that can be called from sandboxed processes.
/// The command struct contains the request data, and the `handle` method processes it.
///
/// # Example
///
/// ```rust,ignore
/// use std::borrow::Cow;
/// use serde::{Serialize, Deserialize};
/// use heel::ipc::IpcCommand;
///
/// #[derive(Clone, Serialize, Deserialize)]
/// struct SearchCommand {
///     query: String,
/// }
///
/// #[derive(Serialize, Deserialize)]
/// struct SearchResult {
///     items: Vec<String>,
/// }
///
/// impl IpcCommand for SearchCommand {
///     type Response = SearchResult;
///
///     fn name(&self) -> String {
///         "search".to_string()
///     }
///
///     fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
///         Cow::Borrowed(&[Cow::Borrowed("query")])  // Enables: search "rust" → search --query "rust"
///     }
///
///     fn apply_args(&mut self, params: &[u8]) -> Result<(), rmp_serde::decode::Error> {
///         *self = rmp_serde::from_slice(params)?;
///         Ok(())
///     }
///
///     async fn handle(&mut self) -> SearchResult {
///         let results = do_search(&self.query).await;
///         SearchResult { items: results }
///     }
/// }
/// ```
pub trait IpcCommand: Serialize + Send + 'static {
    /// The response type returned by this command
    type Response: Serialize + DeserializeOwned + Send;

    /// Command name for wire protocol dispatch
    ///
    /// This name is used to route incoming requests to the correct handler.
    fn name(&self) -> String;

    /// Positional argument names for CLI conversion.
    ///
    /// Returns a list of argument names that map to positional arguments in order.
    /// The wrapper script converts positional args to named args:
    /// - `["query"]` → `command "foo"` becomes `command --query "foo"`
    /// - `["subagent", "prompt"]` → `command research "task"` becomes `command --subagent research --prompt "task"`
    ///
    /// Returns empty slice by default (no positional argument conversion).
    fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[])
    }

    /// Stdin argument name for piped input.
    ///
    /// When set, the wrapper script will capture stdin and pass it as this argument:
    /// `cat file | command "prompt"` → `heel ipc command --<stdin_arg> "<stdin>" --<primary_arg> "prompt"`
    ///
    /// Returns `None` by default (stdin is ignored).
    fn stdin_arg(&self) -> Option<Cow<'static, str>> {
        None
    }

    /// Set the method name on the command after deserialization.
    ///
    /// This is called by the router after deserializing the command from IPC params.
    /// Override this if your command needs the method name (e.g., for dispatching
    /// to different handlers based on the method name).
    ///
    /// Default implementation does nothing.
    fn set_method_name(&mut self, _name: &str) {}

    /// Handle this command and produce a response
    ///
    /// The handler has mutable access to the command data, allowing it to
    /// modify state if needed during processing.
    fn handle(&mut self) -> impl Future<Output = Self::Response> + Send;

    /// Apply arguments from serialized params to this command.
    ///
    /// The router calls this after cloning the command to apply request-specific
    /// arguments while preserving stateful data (registries, connections, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if the params cannot be applied.
    fn apply_args(&mut self, params: &[u8]) -> Result<(), rmp_serde::decode::Error>;
}
