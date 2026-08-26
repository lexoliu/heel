//! Run a command in a sandbox with the default, deny-everything configuration.

// Examples report what the sandbox did, so printing is the point here.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use heel::Sandbox;

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    let sandbox = Sandbox::with_executor(executor_core::tokio::TokioGlobal).await?;
    println!("working directory: {}", sandbox.working_dir().display());

    let output = sandbox
        .command("/bin/echo")
        .arg("hello from the sandbox")
        .output()
        .await?;

    println!("status: {}", output.status);
    print!("stdout: {}", String::from_utf8_lossy(&output.stdout));

    // The working directory is writable; the rest of the home directory is not.
    let denied = sandbox
        .command("/bin/sh")
        .arg("-c")
        .arg("echo scratch > scratch.txt && cat ~/.ssh/id_rsa")
        .output()
        .await?;

    println!(
        "reading ~/.ssh/id_rsa failed as expected: {}",
        !denied.status.success()
    );

    Ok(())
}
