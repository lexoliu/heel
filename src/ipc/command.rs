//! The trait host-side IPC commands implement.

use std::borrow::Cow;
use std::future::Future;

use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::ipc::IpcError;

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
/// use heel::ipc::{IpcCommand, IpcError};
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
///     async fn handle(&self, args: SearchArgs) -> Result<Self::Response, IpcError> {
///         self.client.search(&args.query).await.map_err(IpcError::remote)
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

    /// Whether the invocation's arguments reach the handler verbatim.
    ///
    /// Declared names bind words to `Args` fields on the client side, which
    /// only works when the command line's shape is fixed here. A command whose
    /// arguments are defined by a schema on the host — subcommands, per-variant
    /// fields, anything the client cannot know — returns `true`: the generated
    /// shim forwards every word untouched, `heel ipc` delivers them in
    /// `params["args"]`, and the host-side parser interprets them. `Args` is
    /// then a map or a struct with an `args` field, not a declaration the
    /// client can pre-bind. Declaring positional arguments alongside raw
    /// arguments is a registration error.
    fn raw_args(&self) -> bool {
        false
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
    ///
    /// An error becomes the failure half of the wire response, so `heel ipc`
    /// prints it on standard error and exits non-zero instead of reporting a
    /// successful call that happened to serialize a failure.
    fn handle(
        &self,
        args: Self::Args,
    ) -> impl Future<Output = Result<Self::Response, IpcError>> + Send;
}
