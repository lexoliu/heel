use crate::cli::RunArgs;
use crate::config::MergedConfig;
use crate::error::CliResult;
use crate::sandbox::create_sandbox;
use heel::StdioConfig;

/// Run one program in the sandbox, returning its exit code.
pub async fn execute(args: RunArgs, config: MergedConfig) -> CliResult<i32> {
    let mut sandbox = create_sandbox(&config).await?;
    if config.keep_working_dir {
        sandbox.keep_working_dir();
    }

    let status = sandbox
        .command(args.program())
        .args(args.args())
        .envs(&config.env_set)
        .stdin(StdioConfig::Inherit)
        .stdout(StdioConfig::Inherit)
        .stderr(StdioConfig::Inherit)
        .status()
        .await?;

    Ok(crate::exit_code(status))
}
