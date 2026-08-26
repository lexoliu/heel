use heel::{StdioConfig, VenvManager};

use crate::cli::PythonArgs;
use crate::config::{MergedConfig, merge_python_args};
use crate::error::CliResult;
use crate::sandbox::{create_sandbox, python_venv_config};

/// Run a Python script or REPL in the sandbox, returning its exit code.
pub async fn execute(args: PythonArgs, mut config: MergedConfig) -> CliResult<i32> {
    merge_python_args(&mut config, &args);

    // The environment is prepared before the sandbox starts, because installing
    // packages needs the network access the sandbox denies.
    if let Some(venv) = python_venv_config(&config) {
        VenvManager::create(&venv).await?;
        config.python.venv = Some(venv.path().to_path_buf());
    }

    let mut sandbox = create_sandbox(&config).await?;
    if config.keep_working_dir {
        sandbox.keep_working_dir();
    }

    let mut command = sandbox
        .command(python_executable(&config))
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
fn python_executable(config: &MergedConfig) -> String {
    if let Some(venv) = &config.python.venv {
        let interpreter = if cfg!(windows) {
            venv.join("Scripts").join("python.exe")
        } else {
            venv.join("bin").join("python")
        };
        return interpreter.to_string_lossy().into_owned();
    }

    match &config.python.interpreter {
        Some(interpreter) => interpreter.to_string_lossy().into_owned(),
        None => "python3".to_string(),
    }
}
