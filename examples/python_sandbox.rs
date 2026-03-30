//! Test Python execution in sandbox with venv

use heel::{PythonConfig, Sandbox, SandboxConfigBuilder, VenvConfig, VenvManager};

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    // Create a venv config
    let venv_config = VenvConfig::builder().path("/tmp/sandbox-test-venv").build();

    // Create the venv first
    println!("Creating virtual environment...");
    let venv = VenvManager::create(&venv_config).await?;
    println!("Venv created at: {}", venv.path().display());
    println!("Python: {}", venv.python_path().display());

    // Create sandbox config with Python
    let config = SandboxConfigBuilder::default()
        .python(PythonConfig::builder().venv(venv_config).build())
        .build()?;

    let sandbox = Sandbox::with_config(config).await?;

    // Run a simple Python script
    println!("\nRunning Python in sandbox...");
    let output = sandbox
        .run_python("import sys; print(f'Python {sys.version}')")
        .await?;

    println!("Exit status: {:?}", output.status);
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));

    if !output.status.success() {
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}
