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
async fn working_directory_is_readable_and_writable() {
    let sandbox = default_sandbox().await;
    let output = cmd(&sandbox, "echo written> file.txt && type file.txt").await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "written");
}

#[tokio::test]
async fn files_outside_the_sandbox_are_not_readable() {
    let (_dir, secret) = secret_file();
    let sandbox = default_sandbox().await;

    let output = cmd(&sandbox, &format!("type \"{}\"", secret.display())).await;

    assert!(
        !stdout(&output).contains("token-value"),
        "reading {} must fail, but it printed {:?}",
        secret.display(),
        stdout(&output)
    );
}

#[tokio::test]
async fn files_outside_the_sandbox_are_not_writable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("written.txt");
    let sandbox = default_sandbox().await;

    cmd(&sandbox, &format!("echo escaped> \"{}\"", target.display())).await;

    assert!(
        !target.exists(),
        "{} must not have been created",
        target.display()
    );
}

#[tokio::test]
async fn a_program_written_inside_the_sandbox_cannot_be_executed() {
    // Write-then-execute is the escape a scratch directory would otherwise hand
    // to sandboxed code. A real executable is required: `cmd.exe` interprets a
    // batch file after merely reading it, which execute rights do not govern.
    let sandbox = default_sandbox().await;

    let output = cmd(
        &sandbox,
        "copy /Y %SystemRoot%\\System32\\whoami.exe payload.exe >nul && payload.exe",
    )
    .await;

    assert!(
        !output.status.success(),
        "a program written into the working directory must not run, but it printed {:?}",
        stdout(&output)
    );
}

#[tokio::test]
async fn the_working_directory_is_writable_but_not_executable() {
    // The copy has to succeed, or the test above would pass because the sandbox
    // could not write the payload rather than because it could not run it.
    let sandbox = default_sandbox().await;

    let output = cmd(
        &sandbox,
        "copy /Y %SystemRoot%\\System32\\whoami.exe payload.exe >nul && if exist payload.exe echo COPIED",
    )
    .await;

    assert_eq!(stdout(&output), "COPIED", "{}", stderr(&output));
}

#[tokio::test]
async fn temp_dir_is_inside_the_sandbox() {
    let sandbox = default_sandbox().await;
    let output = cmd(&sandbox, "echo %TEMP%").await;

    assert_eq!(
        stdout(&output),
        sandbox.working_dir().to_string_lossy(),
        "temporary files must land where the sandbox can write"
    );
}

#[tokio::test]
async fn outbound_network_is_denied_by_default() {
    let sandbox = default_sandbox().await;

    // Guard against the test passing because curl is missing rather than
    // because the container has no `internetClient` capability.
    let found = cmd(
        &sandbox,
        "if exist %SystemRoot%\\System32\\curl.exe echo FOUND",
    )
    .await;
    assert_eq!(stdout(&found), "FOUND", "curl must be present to test with");

    let output = cmd(
        &sandbox,
        "curl.exe --silent --max-time 5 http://example.com || echo BLOCKED",
    )
    .await;

    assert!(
        stdout(&output).contains("BLOCKED"),
        "outbound traffic must be refused, got {:?}",
        stdout(&output)
    );
}

#[tokio::test]
async fn proxy_variables_are_absent_without_network_access() {
    let sandbox = default_sandbox().await;
    let output = cmd(&sandbox, "echo %HTTP_PROXY%").await;

    // `cmd.exe` echoes the name back when a variable is not set.
    assert_eq!(stdout(&output), "%HTTP_PROXY%");
    assert_eq!(sandbox.proxy_url(), None);
}
