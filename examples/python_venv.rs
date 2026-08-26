//! Run Python in a sandbox with a prepared virtual environment.
//!
//! The environment is created on the host before the sandbox starts, because
//! installing packages needs the network access the sandbox denies.

// Examples report what the sandbox did, so printing is the point here.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use heel::{PythonConfig, Sandbox, SandboxConfig, VenvConfig, VenvManager};

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    let venv = VenvConfig::builder()
        .path(std::env::temp_dir().join("heel-example-venv"))
        .build();
    VenvManager::create(&venv).await?;

    let config = SandboxConfig::builder()
        .python(PythonConfig::builder().venv(venv).build())
        .build();

    let sandbox =
        Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal).await?;

    let output = sandbox
        .run_python("import sys, pathlib; print(sys.version); print(pathlib.Path.cwd())")
        .await?;

    print!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.status.success() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}
