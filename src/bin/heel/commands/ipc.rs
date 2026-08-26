//! `heel ipc`: invoke a host command from inside a sandbox.
//!
//! The generated command shims exec this with the command's declared argument
//! names, so all parsing happens here rather than in shell script.

use std::collections::BTreeMap;
use std::io::Read;

use heel::IpcClient;
use serde_json::Value;

use crate::cli::IpcArgs;
use crate::error::{CliError, CliResult};

/// Environment variable carrying the sandbox's IPC socket path.
const ENDPOINT_VAR: &str = "HEEL_IPC_ENDPOINT";

/// Send the request and print whatever the handler returned.
pub fn execute(args: IpcArgs) -> CliResult<()> {
    let endpoint = std::env::var_os(ENDPOINT_VAR).ok_or(CliError::MissingIpcEndpoint)?;
    let params = build_params(&args, read_stdin)?;

    let mut client = IpcClient::connect(&endpoint)?;
    let payload = client.call_raw(&args.command, &rmp_serde::to_vec_named(&params)?)?;

    let rendered = render(&payload)?;
    if !rendered.is_empty() {
        println!("{rendered}");
    }
    Ok(())
}

/// Turn command-line arguments into the named parameters the handler expects.
///
/// Leading bare words fill the declared positional names in order; the rest are
/// `--name value` pairs, where a flag with no value is `true`.
fn build_params(
    args: &IpcArgs,
    stdin: impl FnOnce() -> CliResult<String>,
) -> CliResult<BTreeMap<String, Value>> {
    let mut params = BTreeMap::new();
    let mut positional = args.positional.iter();
    let mut rest = args.args.iter().peekable();

    // Positional values must come first, so stop at the first flag.
    while let Some(value) = rest.peek() {
        if value.starts_with('-') {
            break;
        }
        let Some(name) = positional.next() else {
            return Err(CliError::UnexpectedPositional {
                command: args.command.clone(),
                value: (*value).clone(),
            });
        };
        params.insert(name.clone(), Value::String((*value).clone()));
        rest.next();
    }

    while let Some(flag) = rest.next() {
        let Some(name) = flag.strip_prefix("--").filter(|name| !name.is_empty()) else {
            return Err(CliError::UnexpectedArgument {
                command: args.command.clone(),
                value: flag.clone(),
            });
        };

        // `--name=value` and `--name value` are both accepted; a flag followed
        // by another flag or nothing at all is a boolean.
        if let Some((name, value)) = name.split_once('=') {
            params.insert(name.to_string(), Value::String(value.to_string()));
            continue;
        }

        let takes_value = rest.peek().is_some_and(|next| !next.starts_with('-'));
        let value = match takes_value.then(|| rest.next()).flatten() {
            Some(value) => Value::String(value.clone()),
            None => Value::Bool(true),
        };
        params.insert(name.to_string(), value);
    }

    // Reading standard input would block a `--help` invocation whose caller
    // leaves the pipe open, and help never needs the piped data anyway.
    if let Some(name) = &args.stdin_arg
        && !params.contains_key(name)
        && !asks_for_help(&args.args)
    {
        let content = stdin()?;
        if !content.is_empty() {
            params.insert(name.clone(), Value::String(content));
        }
    }

    Ok(params)
}

/// Whether the invocation is asking for help rather than doing work.
fn asks_for_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--help" || arg == "-h")
}

/// Read piped standard input, if any.
fn read_stdin() -> CliResult<String> {
    // A terminal means nothing was piped in, and reading would just hang.
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Ok(String::new());
    }

    let mut content = String::new();
    std::io::stdin().read_to_string(&mut content)?;
    Ok(content)
}

/// Render a MessagePack payload for a terminal.
///
/// A string response is printed as-is; anything else is printed as JSON.
fn render(payload: &[u8]) -> CliResult<String> {
    let value: Value = rmp_serde::from_slice(payload)?;
    Ok(match value {
        Value::Null => String::new(),
        Value::String(text) => text,
        other => serde_json::to_string_pretty(&other)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(command: &str, positional: &[&str], stdin_arg: Option<&str>, rest: &[&str]) -> IpcArgs {
        IpcArgs {
            command: command.to_string(),
            positional: positional.iter().map(|s| s.to_string()).collect(),
            stdin_arg: stdin_arg.map(str::to_string),
            verbose: false,
            args: rest.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn no_stdin() -> CliResult<String> {
        Ok(String::new())
    }

    #[test]
    fn positional_values_fill_declared_names_in_order() {
        let params = build_params(
            &args("run", &["subagent", "prompt"], None, &["research", "do it"]),
            no_stdin,
        )
        .expect("builds");

        assert_eq!(params["subagent"], Value::String("research".into()));
        assert_eq!(params["prompt"], Value::String("do it".into()));
    }

    #[test]
    fn missing_positional_values_are_omitted_rather_than_blank() {
        // A declared name with nothing to fill it must not become an empty
        // string, which the handler could not distinguish from a real value.
        let params =
            build_params(&args("run", &["a", "b"], None, &["only"]), no_stdin).expect("builds");

        assert_eq!(params["a"], Value::String("only".into()));
        assert!(!params.contains_key("b"));
    }

    #[test]
    fn named_flags_are_parsed_in_both_forms() {
        let params = build_params(
            &args("q", &[], None, &["--limit", "3", "--format=json"]),
            no_stdin,
        )
        .expect("builds");

        assert_eq!(params["limit"], Value::String("3".into()));
        assert_eq!(params["format"], Value::String("json".into()));
    }

    #[test]
    fn valueless_flags_are_booleans() {
        let params = build_params(
            &args("q", &[], None, &["--verbose", "--limit", "3"]),
            no_stdin,
        )
        .expect("builds");

        assert_eq!(params["verbose"], Value::Bool(true));
        assert_eq!(params["limit"], Value::String("3".into()));
    }

    #[test]
    fn stdin_fills_the_declared_argument() {
        let params = build_params(&args("sum", &["prompt"], Some("input"), &["brief"]), || {
            Ok("piped text".to_string())
        })
        .expect("builds");

        assert_eq!(params["prompt"], Value::String("brief".into()));
        assert_eq!(params["input"], Value::String("piped text".into()));
    }

    #[test]
    fn help_never_reads_stdin() {
        // Reading here would hang whenever the caller keeps the pipe open,
        // which is the normal case for agent-driven shells.
        let params = build_params(&args("sum", &[], Some("input"), &["--help"]), || {
            panic!("stdin must not be read for --help")
        })
        .expect("builds");

        assert_eq!(params["help"], Value::Bool(true));
        assert!(!params.contains_key("input"));
    }

    #[test]
    fn flags_containing_h_are_not_mistaken_for_help() {
        let mut read = false;
        let params = build_params(
            &args("sum", &[], Some("input"), &["--host", "example"]),
            || {
                read = true;
                Ok("piped".to_string())
            },
        )
        .expect("builds");

        assert_eq!(params["host"], Value::String("example".into()));
        assert_eq!(params["input"], Value::String("piped".into()));
    }

    #[test]
    fn explicit_values_beat_piped_input() {
        let params = build_params(
            &args("sum", &[], Some("input"), &["--input", "explicit"]),
            || panic!("stdin must not override an explicit value"),
        )
        .expect("builds");

        assert_eq!(params["input"], Value::String("explicit".into()));
    }

    #[test]
    fn undeclared_positional_values_are_rejected() {
        let error = build_params(&args("q", &[], None, &["stray"]), no_stdin).expect_err("fails");
        assert!(matches!(error, CliError::UnexpectedPositional { .. }));
    }

    #[test]
    fn single_dash_arguments_are_rejected() {
        let error = build_params(&args("q", &[], None, &["-x"]), no_stdin).expect_err("fails");
        assert!(matches!(error, CliError::UnexpectedArgument { .. }));
    }

    #[test]
    fn responses_render_by_shape() {
        let text = rmp_serde::to_vec_named(&"plain output").unwrap();
        assert_eq!(render(&text).unwrap(), "plain output");

        let structured = rmp_serde::to_vec_named(&serde_json::json!({ "items": [1, 2] })).unwrap();
        assert_eq!(
            render(&structured).unwrap(),
            "{\n  \"items\": [\n    1,\n    2\n  ]\n}"
        );

        let empty = rmp_serde::to_vec_named(&Option::<()>::None).unwrap();
        assert_eq!(render(&empty).unwrap(), "");
    }
}
