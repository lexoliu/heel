//! Test network proxy filtering with AllowList policy
//!
//! This example demonstrates how to create a sandbox with network filtering
//! that only allows access to specific domains.

use heel::{AllowList, Result, Sandbox, SandboxConfig};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Create an AllowList policy that only allows httpbin.org
    let policy = AllowList::new(["httpbin.org", "*.httpbin.org"]);

    // Create sandbox with the network policy
    let config = SandboxConfig::builder().network(policy).build()?;

    let sandbox = Sandbox::with_config(config).await?;
    println!("Sandbox created with proxy at: {}", sandbox.proxy_url());

    // Test with curl using the proxy (via sandbox command)
    println!("\n--- Testing allowed domain (httpbin.org) ---");
    let output = sandbox
        .command("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "http://httpbin.org/get",
        ])
        .output()
        .await?;
    println!(
        "httpbin.org result: exit={}, http_code={}",
        output.status,
        String::from_utf8_lossy(&output.stdout)
    );

    println!("\n--- Testing blocked domain (example.com) ---");
    let output = sandbox
        .command("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "http://example.com",
        ])
        .output()
        .await?;
    println!(
        "example.com result: exit={}, http_code={}",
        output.status,
        String::from_utf8_lossy(&output.stdout)
    );

    println!("\n--- Testing HTTPS to allowed domain ---");
    let output = sandbox
        .command("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://httpbin.org/get",
        ])
        .output()
        .await?;
    println!(
        "HTTPS httpbin.org: exit={}, http_code={}",
        output.status,
        String::from_utf8_lossy(&output.stdout)
    );

    println!("\n--- Testing HTTPS to blocked domain ---");
    let output = sandbox
        .command("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://example.com",
        ])
        .output()
        .await?;
    println!(
        "HTTPS example.com: exit={}, http_code={}",
        output.status,
        String::from_utf8_lossy(&output.stdout)
    );

    println!("\nSandbox will be dropped (proxy stops, working dir cleaned)");

    Ok(())
}
