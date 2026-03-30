//! Test security protections in sandbox with Python

use heel::{Sandbox, SandboxConfigBuilder, SecurityConfig};
use std::path::Path;

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    let scripts_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/scripts");
    let script_path = scripts_dir
        .join("test_security_denied.py")
        .to_string_lossy()
        .to_string();

    println!("=== Security Test (strict mode) ===\n");
    println!("Testing that sensitive data is protected...\n");

    // Test with strict security (default)
    let config = SandboxConfigBuilder::default()
        .security(SecurityConfig::strict())
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

    if output.status.success() {
        println!("PASS: All sensitive data is protected in strict mode");
    } else {
        println!("FAIL: Some sensitive data may be exposed!");
    }

    println!("\n=== Security Test (permissive mode) ===\n");
    println!("Testing that sensitive data is accessible...\n");

    // Test with permissive security
    let config = SandboxConfigBuilder::default()
        .security(SecurityConfig::permissive())
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
