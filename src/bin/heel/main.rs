//! The `heel` command-line interface.
//!
//! Reporting results to the terminal is this binary's purpose, so the
//! workspace lints against printing are lifted here.
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::process::{ExitCode, ExitStatus};

use clap::Parser;
use executor_core::async_executor::AsyncExecutor;
use executor_core::try_init_global_executor;

mod cli;
mod commands;
mod config;
mod error;
mod sandbox;

use cli::{Cli, Commands};
use config::{load_config, merge_config};
use error::CliResult;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let default_filter = if cli.verbose() {
        "heel=debug"
    } else {
        "heel=warn"
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .init();

    let _ = try_init_global_executor(AsyncExecutor::new());

    match smol::block_on(run(cli)) {
        Ok(code) => exit_code_from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch to a subcommand, returning the exit code to report.
async fn run(cli: Cli) -> CliResult<i32> {
    if let Commands::Ipc(args) = cli.command {
        // `heel ipc` runs inside a sandbox and takes no sandbox configuration.
        return commands::ipc::execute(args).map(|()| 0);
    }

    match cli.command {
        Commands::Run(args) => {
            let config = configure(&args.common)?;
            commands::run::execute(args, config).await
        }
        Commands::Shell(args) => {
            let config = configure(&args.common)?;
            commands::shell::execute(args, config).await
        }
        Commands::Python(args) => {
            let config = configure(&args.common)?;
            commands::python::execute(args, config).await
        }
        Commands::Ipc(_) => unreachable!("handled above"),
    }
}

/// Load the config file named by these arguments and merge the two.
fn configure(common: &cli::CommonArgs) -> CliResult<config::MergedConfig> {
    let file_config = load_config(common.config.as_deref())?;
    merge_config(file_config, common)
}

/// The exit code to report for a finished sandboxed process.
///
/// A process killed by a signal has no exit code of its own; the shell
/// convention of `128 + signal` keeps that information rather than flattening
/// every abnormal end into a plain failure.
pub(crate) fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }

    1
}

/// Convert a child's exit code into this process's exit code.
fn exit_code_from(code: i32) -> ExitCode {
    // Exit codes are a single byte on Unix; report anything outside that range
    // as a generic failure rather than silently truncating it to something that
    // could read as success.
    match u8::try_from(code) {
        Ok(code) => ExitCode::from(code),
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_status_maps_to_zero() {
        assert_eq!(exit_code(ExitStatus::default()), 0);
    }

    #[cfg(unix)]
    #[test]
    fn signals_map_to_the_shell_convention() {
        use std::os::unix::process::ExitStatusExt;

        assert_eq!(exit_code(ExitStatus::from_raw(libc::SIGKILL)), 128 + 9);
    }

    #[cfg(unix)]
    #[test]
    fn exit_codes_survive_the_round_trip() {
        use std::os::unix::process::ExitStatusExt;

        // The wait status encodes the exit code in the high byte.
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
    }

    #[test]
    fn out_of_range_codes_report_failure_rather_than_success() {
        assert_eq!(
            format!("{:?}", exit_code_from(256)),
            format!("{:?}", ExitCode::FAILURE)
        );
    }
}
