use std::path::Path;

use heel::{StdioConfig, VenvConfig, VenvManager};

use crate::cli::PythonArgs;
use crate::config::{MergedConfig, merge_python_args};
use crate::error::CliResult;
use crate::sandbox::create_sandbox;

pub async fn execute(args: PythonArgs, mut config: MergedConfig) -> CliResult<()> {
    // Merge Python-specific args into config
    merge_python_args(&mut config, &args);

    // Create venv before sandbox if packages are specified
    if !config.python.packages.is_empty() || config.python.venv.is_some() {
        let venv_path = config
            .python
            .venv
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap().join(".sandbox-venv"));

        let mut venv_builder = VenvConfig::builder().path(&venv_path);

        if let Some(ref interpreter) = config.python.interpreter {
            venv_builder = venv_builder.python(interpreter);
        }
        if !config.python.packages.is_empty() {
            venv_builder = venv_builder.packages(config.python.packages.iter().cloned());
        }
        venv_builder = venv_builder
            .system_site_packages(config.python.system_site_packages)
            .use_uv(config.python.use_uv);

        let venv_config = venv_builder.build();

        // Create venv and install packages (outside sandbox, needs network)
        VenvManager::create(&venv_config).await?;

        // Update config to use the venv path
        config.python.venv = Some(venv_path);
    }

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

        // Determine Python executable
        let python = get_python_executable(&config);

        match args.script {
            Some(script_path) => {
                run_script(&sandbox, &python, &script_path, &args.args, &envs).await?
            }
            None => run_repl(&sandbox, &python, &envs).await?,
        }
        // sandbox dropped here, working dir cleaned up
    };

    std::process::exit(exit_code);
}

fn get_python_executable(config: &MergedConfig) -> String {
    if let Some(ref venv_path) = config.python.venv {
        // Use Python from venv
        let python_path = if cfg!(windows) {
            venv_path.join("Scripts").join("python.exe")
        } else {
            venv_path.join("bin").join("python")
        };
        python_path.to_string_lossy().to_string()
    } else if let Some(ref interpreter) = config.python.interpreter {
        interpreter.to_string_lossy().to_string()
    } else {
        // Use system Python
        "python3".to_string()
    }
}

async fn run_script(
    sandbox: &crate::sandbox::SandboxHandle,
    python: &str,
    script: &Path,
    args: &[String],
    envs: &[(String, String)],
) -> CliResult<i32> {
    let mut cmd = sandbox.command(python);
    cmd = cmd.arg(script.to_string_lossy().as_ref());
    cmd = cmd.args(args);
    for (k, v) in envs {
        cmd = cmd.env(k, v);
    }
    cmd = cmd
        .stdin(StdioConfig::Inherit)
        .stdout(StdioConfig::Inherit)
        .stderr(StdioConfig::Inherit);

    let status = cmd.status().await?;
    Ok(status.code().unwrap_or(1))
}

async fn run_repl(
    sandbox: &crate::sandbox::SandboxHandle,
    python: &str,
    envs: &[(String, String)],
) -> CliResult<i32> {
    let mut cmd = sandbox.command(python);
    for (k, v) in envs {
        cmd = cmd.env(k, v);
    }
    cmd = cmd
        .stdin(StdioConfig::Inherit)
        .stdout(StdioConfig::Inherit)
        .stderr(StdioConfig::Inherit);

    let status = cmd.status().await?;
    Ok(status.code().unwrap_or(1))
}
