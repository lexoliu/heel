//! Debug sandbox to identify the issue

use heel::{AllowAll, Sandbox, SandboxConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Creating sandbox...");
    let config = SandboxConfig::builder().network(AllowAll).build()?;
    let sandbox = smol::block_on(Sandbox::with_config(config))?;
    println!("Sandbox created at: {:?}", sandbox.working_dir());

    println!("\nRunning simple /bin/echo command (captured output)...");
    let output = match smol::block_on(sandbox.command("/bin/echo").args(["hello"]).output()) {
        Ok(output) => output,
        Err(e) => {
            match &e {
                heel::Error::UnsupportedPlatformVersion { .. }
                | heel::Error::NotEnforced(_)
                | heel::Error::InitFailed(_) => {
                    eprintln!("Skipping test due to environment limitations: {}", e);
                    return Ok(());
                }
                _ => {}
            }

            eprintln!("Failed with error: {:#?}", e);
            if let Some(source) = std::error::Error::source(&e) {
                eprintln!("Caused by: {:#?}", source);
            }
            return Err(e.into());
        }
    };

    println!("Success!");
    println!("Exit status: {:?}", output.status);
    println!("Exit code: {:?}", output.status.code());
    println!("Stdout: {:?}", String::from_utf8_lossy(&output.stdout));
    println!("Stderr: {:?}", String::from_utf8_lossy(&output.stderr));

    Ok(())
}
