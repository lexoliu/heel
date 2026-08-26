//! Restrict a sandbox to a fixed set of domains.
//!
//! Sandboxed processes cannot open connections themselves; the kernel only lets
//! them reach the sandbox proxy, which applies the policy to every request.

// Examples report what the sandbox did, so printing is the point here.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use heel::{AllowList, Sandbox, SandboxConfig};

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    let config = SandboxConfig::builder()
        .network(AllowList::new(["example.com", "*.rust-lang.org"]))
        // curl needs to resolve its own CA bundle and libraries.
        .env_passthrough("PATH")
        .build();

    let sandbox =
        Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal).await?;
    println!(
        "proxy: {}",
        sandbox.proxy_url().expect("network is enabled")
    );

    for url in ["http://example.com", "http://crates.io"] {
        let output = sandbox
            .command("/usr/bin/curl")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "-o",
                "/dev/null",
                url,
            ])
            .output()
            .await?;

        println!(
            "{url}: {}",
            if output.status.success() {
                "allowed".to_string()
            } else {
                format!(
                    "blocked ({})",
                    String::from_utf8_lossy(&output.stderr).trim()
                )
            }
        );
    }

    Ok(())
}
