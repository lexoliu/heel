use std::process::ExitCode;

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
use error::{CliResult, to_exit_code};

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize tracing based on verbosity
    let filter = if cli.verbose {
        "heel=debug"
    } else {
        "heel=warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .init();

    // Initialize the global executor
    let _ = try_init_global_executor(AsyncExecutor::new());

    // Run the async main
    let result = smol::block_on(async_main(cli));
    to_exit_code(result)
}

async fn async_main(cli: Cli) -> CliResult<()> {
    let file_config = load_config(cli.config.as_deref())?;

    match cli.command {
        Commands::Run(args) => {
            let config = merge_config(file_config, &args.common)?;
            commands::run::execute(args, config).await
        }
        Commands::Shell(args) => {
            let config = merge_config(file_config, &args.common)?;
            commands::shell::execute(args, config).await
        }
        Commands::Python(args) => {
            let config = merge_config(file_config, &args.common)?;
            commands::python::execute(args, config).await
        }
        Commands::Ipc(args) => commands::ipc::execute(args).await,
    }
}
