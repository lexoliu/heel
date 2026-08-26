use crate::cli::ShellArgs;
use crate::config::MergedConfig;
use crate::error::CliResult;
use crate::sandbox::create_sandbox;

/// Start an interactive shell in the sandbox, returning its exit code.
pub async fn execute(args: ShellArgs, config: MergedConfig) -> CliResult<i32> {
    let mut sandbox = create_sandbox(&config).await?;
    if config.keep_working_dir {
        sandbox.keep_working_dir();
    }

    let shell = args
        .shell
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(default_shell);
    let envs: Vec<(String, String)> = config
        .env_set
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    #[cfg(target_os = "macos")]
    let status = sandbox.run_interactive(&shell, &[], &envs)?;

    #[cfg(not(target_os = "macos"))]
    let status = {
        use heel::StdioConfig;
        sandbox
            .command(&shell)
            .envs(envs.iter().map(|(key, value)| (key, value)))
            .stdin(StdioConfig::Inherit)
            .stdout(StdioConfig::Inherit)
            .stderr(StdioConfig::Inherit)
            .status()
            .await?
    };

    Ok(crate::exit_code(status))
}

/// The user's shell, or a shell that is always present.
fn default_shell() -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    }
}
