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
    // The host stages the program because the container cannot read the
    // system's own binaries, and writes it rather than copying it: `std::fs::copy`
    // goes through CopyFileExW, which can carry the source's own permissions
    // onto the destination instead of letting it inherit.
    let sandbox = default_sandbox().await;
    let working_dir = sandbox.working_dir().to_path_buf();

    let system_root = std::env::var("SystemRoot").expect("SystemRoot is set");
    let program = std::fs::read(format!("{system_root}\\System32\\whoami.exe"))
        .expect("the host reads a program to stage");
    std::fs::write(working_dir.join("source.exe"), program).expect("the host stages a program");
    std::fs::write(working_dir.join("staged.txt"), "staged").expect("the host stages a file");

    // Every probe avoids redirection: what the sandbox may do is checked from
    // the host afterwards, so a shell quirk cannot be mistaken for a denial.
    let readable = cmd(&sandbox, "type staged.txt").await;
    assert_eq!(
        stdout(&readable),
        "staged",
        "the sandbox must be able to read a file staged in its working directory: {}\n\
         working directory: {}\nstaged file: {}",
        stderr(&readable),
        access_control_list(&working_dir),
        access_control_list(&working_dir.join("staged.txt")),
    );

    // The sandbox writes the payload itself, so what governs running it is what
    // a file created in the working directory inherits.
    let copied = cmd(&sandbox, "copy /Y source.exe payload.exe").await;
    let payload = working_dir.join("payload.exe");
    assert!(
        payload.is_file(),
        "the sandbox must be able to write the payload, or running it proves \
         nothing: {}\nworking directory: {}",
        stderr(&copied),
        access_control_list(&working_dir),
    );

    let ran = cmd(&sandbox, "payload.exe").await;
    assert!(
        !ran.status.success(),
        "a program the sandbox wrote must not run, but it printed {:?}\npayload: {}",
        stdout(&ran),
        access_control_list(&payload),
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
