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

use std::path::PathBuf;
use std::process::Output;

use heel::{Sandbox, SandboxConfig, SandboxConfigBuilder};

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

#[tokio::test]
async fn a_granted_directory_opens_children_deeper_than_max_path() {
    // A granted tree is walked so its existing children can be ACL'd, and a
    // tree like a cargo registry can nest past MAX_PATH. The named security
    // APIs refuse such paths unless they are spelled verbatim, and `read_dir`
    // cannot list a directory that deep either, so the grant once failed on
    // the first child it could not even name. `std::fs` accepts verbatim
    // `\\?\` paths and bypasses the limit, which is how the host stages the
    // tree; the grant itself stays an ordinary path, as a caller's would.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut deep = PathBuf::from(format!(r"\\?\{}", dir.path().display()));
    while deep.as_os_str().len() < 300 {
        deep.push("a-directory-deeper-than-max-path");
    }
    std::fs::create_dir_all(&deep).expect("the host stages a tree past MAX_PATH");
    let staged = deep.join("staged.txt");
    std::fs::write(&staged, "deep-value").expect("the host stages a file");

    let config = SandboxConfigBuilder::default().readable(dir.path()).build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    // `type` is a cmd builtin, so it needs no PATH lookup inside the
    // container — the one the other probes lean on for the same reason —
    // and it opens a verbatim `\\?\` path like any other.
    let output = cmd(&sandbox, &format!("type {}", staged.display())).await;
    assert_eq!(stdout(&output), "deep-value", "{}", stderr(&output));
}
