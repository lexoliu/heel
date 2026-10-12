use clap::Parser;

use crate::cli::Cli;
use crate::error::{CliError, CliResult};

pub fn parse() -> CliResult<Cli> {
    let executable = std::env::current_exe()?;
    let command = executable
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or(CliError::InvalidNativeCommand)?;
    if command.eq_ignore_ascii_case("heel") {
        return Ok(Cli::parse());
    }
    let path = executable.with_extension("json");
    let metadata: heel::CommandMeta = serde_json::from_slice(&std::fs::read(&path)?)
        .map_err(|source| CliError::NativeMetadata { path, source })?;
    let mut arguments = vec!["heel".to_owned(), "ipc".to_owned(), command.to_owned()];
    for positional in metadata.positional_args.iter() {
        arguments.extend(["--positional".to_owned(), positional.to_string()]);
    }
    if let Some(stdin_arg) = metadata.stdin_arg {
        arguments.extend(["--stdin-arg".to_owned(), stdin_arg.into_owned()]);
    }
    arguments.push("--".to_owned());
    arguments.extend(std::env::args().skip(1));
    Ok(Cli::parse_from(arguments))
}
