//! The trait host-side IPC commands implement.

use std::borrow::Cow;
use std::future::Future;

use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Arguments for a command that takes none.
///
/// The wire format is always a map of named arguments, so a command without
/// arguments still needs a type to decode that map into. Passing an argument to
/// such a command is an error rather than something silently ignored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

/// A command a sandboxed process can invoke on the host.
///
/// The command value itself holds whatever state the handler needs (API
/// clients, registries, configuration); the per-request data arrives as a
/// separate, typed [`IpcCommand::Args`]. Keeping the two apart means the router
/// never has to clone handler state, and implementations never have to write
/// deserialization glue.
///
/// # Example
///
/// ```rust,ignore
/// use serde::Deserialize;
/// use heel::ipc::IpcCommand;
///
/// struct Search {
///     client: SearchClient,
/// }
///
/// #[derive(Deserialize)]
/// struct SearchArgs {
///     query: String,
/// }
///
/// impl IpcCommand for Search {
///     fn name(&self) -> Cow<'static, str> {
///         "search".into()
///     }
///
///     // Enables `search "rust"` in the sandbox, mapped to `--query rust`.
///     fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
///         Cow::Borrowed(&[Cow::Borrowed("query")])
///     }
///
///     type Args = SearchArgs;
///     type Response = Vec<String>;
///
///     async fn handle(&self, args: SearchArgs) -> Self::Response {
///         self.client.search(&args.query).await
///     }
/// }
/// ```
pub trait IpcCommand: Send + Sync + 'static {
    /// The name sandboxed processes invoke.
    ///
    /// This is also the file name of the generated wrapper script, so it must
    /// match `[A-Za-z][A-Za-z0-9_-]*`.
    ///
    /// Taken from the value rather than the type so that one command type can
    /// serve many names: a host exposing tools it discovered at runtime cannot
    /// know them at compile time. Return a `Cow::Borrowed` for a fixed name and
    /// nothing is allocated.
    fn name(&self) -> Cow<'static, str>;

    /// Names for arguments that may be passed positionally.
    ///
    /// `["query"]` lets `search "foo"` stand in for `search --query foo`;
    /// `["subagent", "prompt"]` maps `run a "b"` to `--subagent a --prompt b`.
    fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[])
    }

    /// Name of the argument that receives piped standard input.
    ///
    /// With `Some("input")`, `cat file | summarize "brief"` arrives as
    /// `--input <file contents> --prompt brief`. Standard input is not read
    /// when the invocation asks for help.
    fn stdin_arg(&self) -> Option<Cow<'static, str>> {
        None
    }

    /// Per-request arguments, deserialized from the wire.
    type Args: DeserializeOwned + Send;

    /// The value returned to the sandboxed caller.
    type Response: Serialize + Send;

    /// Handle one request.
    fn handle(&self, args: Self::Args) -> impl Future<Output = Self::Response> + Send;
}
