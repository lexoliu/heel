//! Basic sandbox example

use heel::Sandbox;

#[tokio::main]
async fn main() -> heel::Result<()> {
    // Enable tracing for debug output
    tracing_subscriber::fmt::init();

    // Create a sandbox with default configuration (network denied)
    let sandbox = Sandbox::new().await?;

    // Run a simple command in the sandbox
    let output = sandbox
        .command("echo")
        .arg("Hello from sandbox!")
        .output()
        .await?;

    println!("Exit status: {:?}", output.status);
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    Ok(())
}
