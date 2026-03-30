//! Test that network is blocked in the sandbox

use heel::Sandbox;

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    let sandbox = Sandbox::new().await?;

    // Try to make a network request - this should fail
    let output = sandbox
        .command("curl")
        .arg("-s")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}")
        .arg("https://httpbin.org/get")
        .output()
        .await?;

    println!("Exit status: {:?}", output.status);
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    if output.status.success() {
        println!("\nWARNING: Network request succeeded - sandbox may not be working!");
    } else {
        println!("\nSUCCESS: Network request was blocked by sandbox!");
    }

    Ok(())
}
