//! Test GPU access in sandbox with Python

use heel::{Sandbox, SandboxConfigBuilder, SecurityConfig};
use std::path::Path;

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    let scripts_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/scripts");
    let script_path = scripts_dir
        .join("test_gpu.py")
        .to_string_lossy()
        .to_string();

    println!("=== GPU Access Test (allow_gpu=true) ===\n");

    // Test with GPU access enabled (default)
    let config = SandboxConfigBuilder::default()
        .security(SecurityConfig::builder().allow_gpu(true).build())
        .readable_path(&scripts_dir)
        .build()?;

    let sandbox = Sandbox::with_config(config).await?;

    let output = sandbox
        .command("python3")
        .arg(&script_path)
        .output()
        .await?;

    println!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    println!("Exit status: {:?}\n", output.status);

    println!("=== GPU Access Test (allow_gpu=false) ===\n");

    // Test with GPU access disabled
    let config = SandboxConfigBuilder::default()
        .security(SecurityConfig::builder().allow_gpu(false).build())
        .readable_path(&scripts_dir)
        .build()?;

    let sandbox = Sandbox::with_config(config).await?;

    let output = sandbox
        .command("python3")
        .arg(&script_path)
        .output()
        .await?;

    println!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    println!("Exit status: {:?}", output.status);

    Ok(())
}
