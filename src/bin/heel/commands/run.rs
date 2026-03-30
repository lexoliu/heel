use heel::StdioConfig;

use crate::cli::RunArgs;
use crate::config::MergedConfig;
use crate::error::CliResult;
use crate::sandbox::create_sandbox;

pub async fn execute(args: RunArgs, config: MergedConfig) -> CliResult<()> {
    let exit_code = {
        let mut sandbox = create_sandbox(&config).await?;

        if config.keep_working_dir {
            sandbox.keep_working_dir();
        }

        // Build environment variables from config
        let envs: Vec<(String, String)> = config
            .env_set
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        // Run the command with inherited stdio
        let mut cmd = sandbox.command(&args.program);
        cmd = cmd.args(&args.args);
        for (k, v) in &envs {
            cmd = cmd.env(k, v);
        }
        cmd = cmd
            .stdin(StdioConfig::Inherit)
            .stdout(StdioConfig::Inherit)
            .stderr(StdioConfig::Inherit);

        let status = cmd.status().await?;
        status.code().unwrap_or(1)
        // sandbox dropped here, working dir cleaned up
    };

    std::process::exit(exit_code);
}
