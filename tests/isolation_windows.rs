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
    //
    // The host stages the source inside the working directory because the
    // container cannot read the system's own binaries, so copying one from
    // System32 fails before it proves anything.
    let sandbox = default_sandbox().await;

    let system_root = std::env::var("SystemRoot").expect("SystemRoot is set");
    let source = sandbox.working_dir().join("source.exe");
    std::fs::copy(format!("{system_root}\\System32\\whoami.exe"), &source)
        .expect("the host stages an executable the sandbox can read");

    // Each step is checked on its own: "access is denied" from `copy` does not
    // say whether the source could not be read or the destination could not be
    // written, and the difference decides what is actually enforced here.
    let readable = cmd(
        &sandbox,
        "if exist source.exe (type source.exe >nul && echo READABLE) else (echo MISSING)",
    )
    .await;
    assert_eq!(
        stdout(&readable),
        "READABLE",
        "the sandbox must be able to read a file staged in its working directory: {}",
        stderr(&readable)
    );

    let created = cmd(
        &sandbox,
        "echo placeholder> payload.exe && if exist payload.exe echo CREATED",
    )
    .await;
    assert_eq!(
        stdout(&created),
        "CREATED",
        "the sandbox must be able to create a file named like a program: {}",
        stderr(&created)
    );

    // The sandbox writes the payload itself, so what governs running it is what
    // a file created in the working directory inherits.
    let copied = cmd(
        &sandbox,
        "copy /Y source.exe payload.exe >nul && if exist payload.exe echo COPIED",
    )
    .await;
    assert_eq!(
        stdout(&copied),
        "COPIED",
        "the sandbox must be able to write the payload, or running it proves nothing: {}",
        stderr(&copied)
    );

    let ran = cmd(&sandbox, "payload.exe").await;
    assert!(
        !ran.status.success(),
        "a program the sandbox wrote must not run, but it printed {:?}",
        stdout(&ran)
    );
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
