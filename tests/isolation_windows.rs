//! What the Windows sandbox does beyond the shared guarantees.
//!
//! The guarantees every backend owes -- reachable paths are the ones granted,
//! execution is a right of its own, a container without `internetClient` has no
//! network -- are asserted once in `guarantees.rs`, with this platform supplying
//! only the way to ask. What is left here is what only an AppContainer does:
//! Windows hands each container a temp directory inside its own package folder
//! and redirects `TEMP` there, overriding whatever the sandbox sets.

#![cfg(target_os = "windows")]
#![allow(clippy::unwrap_used)]

use std::process::Output;

use heel::{Sandbox, SandboxConfig};

/// Run `script` with `cmd.exe` inside `sandbox`.
async fn cmd(sandbox: &Sandbox<impl heel::NetworkPolicy>, script: &str) -> Output {
    sandbox
        .command("cmd.exe")
        .arg("/C")
        .arg(script)
        .output()
        .await
        .expect("the shell runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_string()
}

/// A sandbox with the default, deny-everything configuration.
async fn default_sandbox() -> Sandbox {
    Sandbox::with_config_and_executor(SandboxConfig::new(), executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts")
}

#[tokio::test]
async fn the_temp_directory_is_private_to_the_container() {
    // Windows gives each AppContainer its own temp directory inside its package
    // folder and redirects `TEMP` there, overriding whatever the sandbox sets.
    // That is stronger than pointing at the working directory, not weaker: no
    // other container and no other user can read it.
    let sandbox = default_sandbox().await;

    let output = cmd(&sandbox, "echo %TEMP%").await;
    let temp = stdout(&output);
    assert!(
        temp.contains("\\Packages\\"),
        "temp must be the container's own, got {temp:?}"
    );

    let written = cmd(
        &sandbox,
        "echo written> %TEMP%\\probe.txt && type %TEMP%\\probe.txt",
    )
    .await;
    assert_eq!(stdout(&written), "written", "{}", stderr(&written));
}
