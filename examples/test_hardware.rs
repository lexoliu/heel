//! Test general hardware access in sandbox with Python

use heel::{Sandbox, SandboxConfigBuilder, SecurityConfig};
use std::path::Path;

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    let scripts_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/scripts");
    let script_path = scripts_dir
        .join("test_hardware.py")
        .to_string_lossy()
        .to_string();

    println!("=== Hardware Access Test (allow_hardware=true) ===\n");

    // Test with hardware access enabled
    // Also need to allow access to system_profiler for hardware enumeration
    let config = SandboxConfigBuilder::default()
        .security(SecurityConfig::builder().allow_hardware(true).build())
        .readable_path(&scripts_dir)
        .readable_path("/usr/sbin")
        .executable_path("/usr/sbin/system_profiler")
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

    println!("=== Hardware Access Test (allow_hardware=false, strict mode) ===\n");

    // Test with hardware access disabled (strict mode default)
    // Still allow system_profiler to show that IOKit access is blocked
    let config = SandboxConfigBuilder::default()
        .security(SecurityConfig::strict())
        .readable_path(&scripts_dir)
        .readable_path("/usr/sbin")
        .executable_path("/usr/sbin/system_profiler")
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
