//! Dispatch of IPC requests to registered command handlers.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::ipc::command::IpcCommand;
use crate::ipc::protocol::IpcError;

/// A registered handler, erased so that commands of different types can share
/// one dispatch table.
type ErasedHandler = Arc<
    dyn Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, IpcError>> + Send>>
        + Send
        + Sync,
>;

/// How a command's arguments may be written on the sandbox command line.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommandMeta {
    /// Argument names that may be given positionally, in order.
    pub positional_args: Cow<'static, [Cow<'static, str>]>,
    /// Argument that receives piped standard input, if any.
    pub stdin_arg: Option<Cow<'static, str>>,
    /// Whether every argument reaches the handler verbatim in `params["args"]`.
    #[serde(default)]
    pub raw_args: bool,
}

/// Whether a name is usable as a command or argument name.
///
/// Names become file names and command-line flags, so they are restricted to a
/// shape that needs no quoting anywhere it is used.
fn is_valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

fn assert_valid_identifier(kind: &str, value: &str) {
    assert!(
        is_valid_identifier(value),
        "invalid IPC {kind} '{value}': expected [A-Za-z][A-Za-z0-9_-]*"
    );
}

/// Routes IPC requests to registered [`IpcCommand`] handlers.
///
/// Registration is type-safe; dispatch is by name.
#[derive(Default)]
pub struct IpcRouter {
    handlers: BTreeMap<Cow<'static, str>, ErasedHandler>,
    metadata: BTreeMap<Cow<'static, str>, CommandMeta>,
}

impl IpcRouter {
    /// Create an empty router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a command.
    ///
    /// The command value is shared across requests, so handler state is set up
    /// once rather than rebuilt per call.
    ///
    /// # Panics
    ///
    /// Panics if the command's name or any of its argument names is not a valid
    /// identifier, or if the name is already registered. Both are mistakes in
    /// the program rather than runtime conditions, and both would otherwise
    /// produce a broken wrapper script inside the sandbox.
    pub fn register<C: IpcCommand>(mut self, command: C) -> Self {
        let name = command.name();
        let positional_args = command.positional_args();
        let stdin_arg = command.stdin_arg();

        assert_valid_identifier("command name", &name);
        assert!(
            name.as_ref() != "heel",
            "heel is reserved for the IPC launcher"
        );
        for arg in positional_args.iter() {
            assert_valid_identifier("positional argument name", arg);
        }
        if let Some(arg) = &stdin_arg {
            assert_valid_identifier("stdin argument name", arg);
        }
        assert!(
            !self.handlers.contains_key(&name),
            "IPC command '{name}' is already registered"
        );
        let raw_args = command.raw_args();
        assert!(
            !raw_args || positional_args.is_empty(),
            "IPC command '{name}' cannot declare positional arguments with raw_args"
        );

        let command = Arc::new(command);
        let handler: ErasedHandler = Arc::new(move |params: Vec<u8>| {
            let command = Arc::clone(&command);
            Box::pin(async move {
                let args = rmp_serde::from_slice::<C::Args>(&params)?;
                let response = command.handle(args).await?;
                Ok(rmp_serde::to_vec_named(&response)?)
            })
        });

        self.metadata.insert(
            name.clone(),
            CommandMeta {
                positional_args,
                stdin_arg,
                raw_args,
            },
        );
        self.handlers.insert(name, handler);
        self
    }

    /// Dispatch one request. Called by the IPC server.
    pub async fn handle(&self, method: &str, params: Vec<u8>) -> Result<Vec<u8>, IpcError> {
        let handler = self
            .handlers
            .get(method)
            .ok_or_else(|| IpcError::UnknownMethod(method.to_string()))?;

        handler(params).await
    }

    /// The registered commands and how their arguments may be written.
    pub fn methods(&self) -> impl Iterator<Item = (&str, &CommandMeta)> {
        self.metadata
            .iter()
            .map(|(name, meta)| (name.as_ref(), meta))
    }
}

impl std::fmt::Debug for IpcRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcRouter")
            .field("commands", &self.metadata.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::NoArgs;
    use serde::{Deserialize, Serialize};

    struct Doubler;

    #[derive(Deserialize)]
    struct DoublerArgs {
        value: i32,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct DoublerResponse {
        doubled: i32,
    }

    impl IpcCommand for Doubler {
        fn name(&self) -> Cow<'static, str> {
            "double".into()
        }
        fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
            Cow::Borrowed(&[Cow::Borrowed("value")])
        }

        type Args = DoublerArgs;
        type Response = DoublerResponse;

        async fn handle(&self, args: DoublerArgs) -> Result<DoublerResponse, IpcError> {
            Ok(DoublerResponse {
                doubled: args.value * 2,
            })
        }
    }

    /// A command whose handler keeps state across requests.
    struct Counter {
        greeting: String,
    }

    #[derive(Deserialize)]
    struct CounterArgs {
        name: String,
    }

    impl IpcCommand for Counter {
        fn name(&self) -> Cow<'static, str> {
            "greet".into()
        }

        type Args = CounterArgs;
        type Response = String;

        async fn handle(&self, args: CounterArgs) -> Result<String, IpcError> {
            Ok(format!("{}, {}!", self.greeting, args.name))
        }
    }

    #[test]
    fn dispatches_to_the_registered_handler() {
        smol::block_on(async {
            let router = IpcRouter::new().register(Doubler);
            let params = rmp_serde::to_vec_named(&serde_json::json!({ "value": 21 })).unwrap();

            let response = router.handle("double", params).await.unwrap();
            let response: DoublerResponse = rmp_serde::from_slice(&response).unwrap();

            assert_eq!(response, DoublerResponse { doubled: 42 });
        });
    }

    /// A command whose words go to the host-side parser untouched.
    struct Tool;

    #[derive(Deserialize)]
    struct ToolArgs {
        args: Vec<String>,
    }

    impl IpcCommand for Tool {
        fn name(&self) -> Cow<'static, str> {
            "tool".into()
        }

        fn raw_args(&self) -> bool {
            true
        }

        type Args = ToolArgs;
        type Response = Vec<String>;

        async fn handle(&self, args: ToolArgs) -> Result<Vec<String>, IpcError> {
            Ok(args.args)
        }
    }

    #[test]
    fn raw_args_commands_receive_argv_verbatim() {
        smol::block_on(async {
            let router = IpcRouter::new().register(Tool);
            let params = rmp_serde::to_vec_named(
                &serde_json::json!({ "args": ["open", "--detail", "full"] }),
            )
            .unwrap();

            let response = router.handle("tool", params).await.unwrap();
            let response: Vec<String> = rmp_serde::from_slice(&response).unwrap();

            assert_eq!(response, ["open", "--detail", "full"]);
            assert!(router.methods().next().unwrap().1.raw_args);
        });
    }

    /// A command that opts into raw argv may not also declare positionals.
    struct BothBindings;

    impl IpcCommand for BothBindings {
        fn name(&self) -> Cow<'static, str> {
            "both".into()
        }
        fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
            Cow::Borrowed(&[Cow::Borrowed("query")])
        }
        fn raw_args(&self) -> bool {
            true
        }

        type Args = NoArgs;
        type Response = ();

        async fn handle(&self, _args: NoArgs) -> Result<(), IpcError> {
            Ok(())
        }
    }

    #[test]
    #[should_panic(expected = "cannot declare positional arguments with raw_args")]
    fn raw_args_rejects_declared_positionals() {
        let _ = IpcRouter::new().register(BothBindings);
    }

    #[test]
    fn handler_state_is_shared_across_requests() {
        smol::block_on(async {
            let router = IpcRouter::new().register(Counter {
                greeting: "Hello".to_string(),
            });

            for name in ["ada", "grace"] {
                let params = rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).unwrap();
                let response = router.handle("greet", params).await.unwrap();
                let response: String = rmp_serde::from_slice(&response).unwrap();
                assert_eq!(response, format!("Hello, {name}!"));
            }
        });
    }

    #[test]
    fn unknown_methods_are_reported() {
        smol::block_on(async {
            let router = IpcRouter::new();
            let result = router.handle("unknown", Vec::new()).await;
            assert!(matches!(result, Err(IpcError::UnknownMethod(_))));
        });
    }

    #[test]
    fn malformed_arguments_are_reported() {
        smol::block_on(async {
            let router = IpcRouter::new().register(Doubler);
            let params = rmp_serde::to_vec_named(&serde_json::json!({ "wrong": 1 })).unwrap();
            let result = router.handle("double", params).await;
            assert!(matches!(result, Err(IpcError::Deserialization(_))));
        });
    }

    #[test]
    fn metadata_comes_from_the_command_type() {
        let router = IpcRouter::new().register(Doubler);
        let methods: Vec<_> = router.methods().collect();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].0, "double");
        assert_eq!(
            methods[0].1.positional_args.as_ref(),
            &[Cow::Borrowed("value")]
        );
        assert_eq!(methods[0].1.stdin_arg, None);
    }

    struct BadName;

    impl IpcCommand for BadName {
        fn name(&self) -> Cow<'static, str> {
            "bad/name".into()
        }

        type Args = NoArgs;
        type Response = ();

        async fn handle(&self, _args: NoArgs) -> Result<(), IpcError> {
            Ok(())
        }
    }

    #[test]
    #[should_panic(expected = "invalid IPC command name")]
    fn invalid_command_names_are_rejected() {
        let _ = IpcRouter::new().register(BadName);
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn duplicate_registration_is_rejected() {
        let _ = IpcRouter::new().register(Doubler).register(Doubler);
    }
}
