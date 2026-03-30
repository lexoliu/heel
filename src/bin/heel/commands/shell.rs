use crate::cli::ShellArgs;
use crate::config::MergedConfig;
use crate::error::CliResult;
use crate::sandbox::create_sandbox;

pub async fn execute(args: ShellArgs, config: MergedConfig) -> CliResult<()> {
    let exit_code = {
        let mut sandbox = create_sandbox(&config).await?;

        if config.keep_working_dir {
            sandbox.keep_working_dir();
        }

        let shell = args
            .shell
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(default_shell);

        // Build environment variables from config
        let envs: Vec<(String, String)> = config
            .env_set
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        #[cfg(target_os = "macos")]
        {
            let status = sandbox.run_interactive(&shell, &[], &envs)?;
            status.code()
        }

        #[cfg(not(target_os = "macos"))]
        {
            let status = sandbox.run_shell(&shell, &[], &envs).await?;
            status.code().unwrap_or(1)
        }
        // sandbox dropped here, working dir cleaned up
    };

    std::process::exit(exit_code);
}

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
