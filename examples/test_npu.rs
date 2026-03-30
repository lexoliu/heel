//! Test NPU/Neural Engine access in sandbox with Python

use heel::{Sandbox, SandboxConfigBuilder, SecurityConfig};
use std::path::Path;

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    let scripts_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/scripts");
    let script_path = scripts_dir
        .join("test_npu.py")
        .to_string_lossy()
        .to_string();

    println!("=== NPU Access Test (allow_npu=true) ===\n");

    // Test with NPU access enabled (default)
    let config = SandboxConfigBuilder::default()
        .security(SecurityConfig::builder().allow_npu(true).build())
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

    println!("=== NPU Access Test (allow_npu=false) ===\n");

    // Test with NPU access disabled
    let config = SandboxConfigBuilder::default()
        .security(SecurityConfig::builder().allow_npu(false).build())
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
