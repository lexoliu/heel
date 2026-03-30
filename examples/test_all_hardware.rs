//! Comprehensive hardware access test - GPU, NPU, and general hardware

use heel::{Sandbox, SandboxConfigBuilder, SecurityConfig};
use std::path::Path;

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    let scripts_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/scripts");
    let gpu_script = scripts_dir
        .join("test_gpu.py")
        .to_string_lossy()
        .to_string();
    let npu_script = scripts_dir
        .join("test_npu.py")
        .to_string_lossy()
        .to_string();
    let hw_script = scripts_dir
        .join("test_hardware.py")
        .to_string_lossy()
        .to_string();

    println!("=== Comprehensive Hardware Test ===\n");
    println!("Testing with permissive config (all hardware allowed)...\n");

    let config = SandboxConfigBuilder::default()
        .security(SecurityConfig::permissive())
        .readable_path(&scripts_dir)
        .build()?;

    let sandbox = Sandbox::with_config(config).await?;

    // Test GPU
    println!("--- GPU Test ---");
    let output = sandbox.command("python3").arg(&gpu_script).output().await?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    // Test NPU
    println!("\n--- NPU Test ---");
    let output = sandbox.command("python3").arg(&npu_script).output().await?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    // Test Hardware
    println!("\n--- General Hardware Test ---");
    let output = sandbox.command("python3").arg(&hw_script).output().await?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    println!("\n=== Testing with strict config ===\n");
    println!("(GPU and NPU allowed, general hardware denied)\n");

    let config = SandboxConfigBuilder::default()
        .security(SecurityConfig::strict())
        .readable_path(&scripts_dir)
        .build()?;

    let sandbox = Sandbox::with_config(config).await?;

    // Test Hardware (should fail some checks)
    println!("--- General Hardware Test (strict) ---");
    let output = sandbox.command("python3").arg(&hw_script).output().await?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    println!("Exit status: {:?}", output.status);

    Ok(())
}
