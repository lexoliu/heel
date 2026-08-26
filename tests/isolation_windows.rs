//! What the Windows sandbox must actually prevent.
//!
//! The same guarantees `isolation.rs` asserts on macOS and Linux, expressed for
//! an AppContainer: reachable paths are the ones granted by ACL, execution is a
//! right of its own, and a container without `internetClient` has no network.
//!
//! These are a separate file rather than a platform arm of `isolation.rs`
//! because every script differs -- `cmd.exe` is not a POSIX shell -- and because
//! the write-then-execute check has to use a real executable: a batch file is
//! read and interpreted by `cmd.exe`, so it would prove nothing about execute
//! rights.

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

/// The access control list Windows reports for a path, as the host sees it.
///
/// An AppContainer's reach is decided entirely by these entries, so when the
/// container cannot read something the entries are the evidence: they say
/// whether the grant landed on the directory and whether it reached the file.
fn access_control_list(path: &std::path::Path) -> String {
    let output = std::process::Command::new("icacls")
        .arg(path)
        .output()
        .expect("icacls runs");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// A sandbox with the default, deny-everything configuration.
async fn default_sandbox() -> Sandbox {
    Sandbox::with_config_and_executor(SandboxConfig::new(), executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts")
}

/// A file outside the sandbox that must stay unreadable.
fn secret_file() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, "token-value").expect("writes");
    (dir, path)
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
