use heel::{StdioConfig, VenvConfig, VenvManager};

use crate::cli::PythonArgs;
use crate::config::{MergedConfig, merge_python_args};
use crate::error::CliResult;
use crate::sandbox::{create_sandbox, python_venv_config};

/// Run a Python script or REPL in the sandbox, returning its exit code.
pub async fn execute(args: PythonArgs, mut config: MergedConfig) -> CliResult<i32> {
    merge_python_args(&mut config, &args);
    let paths = config.resolve_paths().await?;

    // The environment is prepared before the sandbox starts, because installing
    // packages needs the network access the sandbox denies.
    let venv = python_venv_config(&config, &paths);
    if let Some(venv) = &venv {
        VenvManager::create(venv).await?;
    }

    let mut sandbox = create_sandbox(&config, &paths).await?;
    if config.keep_working_dir {
        sandbox.keep_working_dir();
    }

    let mut command = sandbox
        .command(python_executable(&config, venv.as_ref()))
        .envs(&config.env_set);

    if let Some(script) = args.script() {
        command = command.arg(script).args(args.args());
    }

    let status = command
        .stdin(StdioConfig::Inherit)
        .stdout(StdioConfig::Inherit)
        .stderr(StdioConfig::Inherit)
        .status()
        .await?;

    Ok(crate::exit_code(status))
}

/// The interpreter to run inside the sandbox.
fn python_executable(config: &MergedConfig, venv: Option<&VenvConfig>) -> String {
    if let Some(venv) = venv {
        let interpreter = if cfg!(windows) {
            venv.path().join("Scripts").join("python.exe")
        } else {
            venv.path().join("bin").join("python")
        };
        return interpreter.to_string_lossy().into_owned();
    }

    match &config.python.interpreter {
        Some(interpreter) => interpreter.to_string_lossy().into_owned(),
        None => "python3".to_string(),
    }
}
