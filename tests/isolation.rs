//! What the sandbox must actually prevent.
//!
//! These tests run real programs inside a real sandbox and assert that
//! forbidden operations fail. Asserting on the generated profile text would
//! only prove that the generator wrote what it was told to; the point here is
//! that the kernel enforces it.

#![cfg(any(target_os = "macos", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Output;

use heel::{Sandbox, SandboxConfig, SandboxConfigBuilder};

/// Run `script` with `/bin/sh` inside `sandbox`.
async fn sh(sandbox: &Sandbox<impl heel::NetworkPolicy>, script: &str) -> Output {
    sandbox
        .command("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .await
        .expect("the shell runs")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_string()
}

fn stdout(output: &Output) -> String {
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
    let output = sh(&sandbox, "echo written > file.txt && cat file.txt").await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "written");
}

#[tokio::test]
async fn files_outside_the_sandbox_are_not_readable() {
    let (_dir, secret) = secret_file();
    let sandbox = default_sandbox().await;

    let output = sh(&sandbox, &format!("cat {}", secret.display())).await;

    assert!(
        !output.status.success(),
        "reading {} must fail, but it printed {:?}",
        secret.display(),
        stdout(&output)
    );
    assert!(!stdout(&output).contains("token-value"));
}

#[tokio::test]
async fn an_explicitly_readable_path_is_readable() {
    let (_dir, secret) = secret_file();
    let config = SandboxConfigBuilder::default()
        .readable_path(secret.parent().expect("has a parent"))
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let output = sh(&sandbox, &format!("cat {}", secret.display())).await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "token-value");
}

#[tokio::test]
async fn an_explicit_allow_beats_a_default_protection() {
    // The protections are defaults, not overrides: a caller who names a path
    // must get it even when a protection rule would otherwise cover it. The
    // sandbox's own working directory relies on this, since it can live
    // anywhere the caller puts it.
    let home = std::env::var_os("HOME").expect("HOME is set");
    let scratch = Path::new(&home).join(".heel-integration-scratch");
    std::fs::create_dir_all(&scratch).expect("creates");
    std::fs::write(scratch.join("data.txt"), "visible").expect("writes");

    let config = SandboxConfigBuilder::default()
        .readable_path(&scratch)
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let output = sh(&sandbox, &format!("cat {}/data.txt", scratch.display())).await;
    std::fs::remove_dir_all(&scratch).ok();

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "visible");
}

#[tokio::test]
async fn files_outside_the_sandbox_are_not_writable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("written.txt");
    let sandbox = default_sandbox().await;

    let output = sh(&sandbox, &format!("echo pwned > {}", target.display())).await;

    assert!(!output.status.success(), "writing outside must fail");
    assert!(!target.exists(), "the file must not have been created");
}

#[tokio::test]
async fn a_program_written_inside_the_sandbox_cannot_be_executed() {
    // Write-then-execute is the escape a scratch directory would otherwise
    // hand to sandboxed code.
    let sandbox = default_sandbox().await;

    let output = sh(
        &sandbox,
        "printf '#!/bin/sh\\necho executed\\n' > payload.sh && chmod +x ./payload.sh && ./payload.sh",
    )
    .await;

    assert!(
        !output.status.success(),
        "executing a file from the working directory must fail: {:?}",
        stdout(&output)
    );
    assert_ne!(stdout(&output), "executed");
}

#[tokio::test]
async fn a_program_written_to_shared_temp_cannot_be_executed() {
    // Permissive makes the whole filesystem writable, which is exactly when
    // shared temp needs the same no-exec protection as the working directory.
    let config = SandboxConfigBuilder::default()
        .filesystem_strict(false)
        .writable_file_system(true)
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let output = sh(
        &sandbox,
        "printf '#!/bin/sh\\necho executed\\n' > /tmp/heel-payload.sh \
         && chmod +x /tmp/heel-payload.sh && /tmp/heel-payload.sh",
    )
    .await;
    std::fs::remove_file("/tmp/heel-payload.sh").ok();

    assert_ne!(
        stdout(&output),
        "executed",
        "shared temp must not be executable"
    );
}

#[tokio::test]
async fn permissive_mode_can_still_run_programs() {
    // Permissive gives up the write-then-execute guarantee, but a sandbox that
    // cannot exec at all is broken rather than permissive.
    let config = SandboxConfigBuilder::default()
        .filesystem_strict(false)
        .writable_file_system(true)
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let output = sh(&sandbox, "echo permissive-ok").await;
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "permissive-ok");
}

#[tokio::test]
async fn shared_temp_is_not_writable_outside_permissive_mode() {
    let config = SandboxConfigBuilder::default()
        .filesystem_strict(false)
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let probe = std::env::temp_dir().join("heel-shared-temp-probe");
    let output = sh(&sandbox, &format!("echo x > {}", probe.display())).await;

    assert!(!output.status.success(), "shared temp must not be writable");
    assert!(!probe.exists());
    std::fs::remove_file(&probe).ok();
}

#[tokio::test]
async fn tmpdir_is_inside_the_sandbox() {
    let sandbox = default_sandbox().await;
    let output = sh(&sandbox, "printf %s \"$TMPDIR\"").await;

    assert_eq!(stdout(&output), sandbox.working_dir().to_string_lossy());
}

#[tokio::test]
async fn the_host_path_is_not_leaked_into_the_sandbox() {
    let sandbox = default_sandbox().await;
    let output = sh(&sandbox, "printf %s \"$PATH\"").await;

    assert_eq!(stdout(&output), heel::DEFAULT_SANDBOX_PATH);
}

#[tokio::test]
async fn the_host_path_can_be_forwarded_explicitly() {
    let config = SandboxConfigBuilder::default()
        .env_passthrough("PATH")
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let output = sh(&sandbox, "printf %s \"$PATH\"").await;

    assert_eq!(stdout(&output), std::env::var("PATH").expect("PATH is set"));
}

#[tokio::test]
async fn caller_environment_overrides_what_the_sandbox_injects() {
    let sandbox = default_sandbox().await;
    let output = sandbox
        .command("/bin/sh")
        .arg("-c")
        .arg("printf %s \"$TMPDIR\"")
        .env("TMPDIR", "/custom")
        .output()
        .await
        .expect("runs");

    assert_eq!(stdout(&output), "/custom");
}

#[tokio::test]
async fn outbound_network_is_denied_by_default() {
    let sandbox = default_sandbox().await;

    // Guard against the test passing because curl is missing rather than
    // because the connection was refused.
    let found = sh(&sandbox, "command -v curl").await;
    assert!(
        found.status.success(),
        "curl must be reachable in the sandbox"
    );

    // Connecting is denied in the kernel, so this fails fast rather than
    // waiting for the timeout.
    let output = sh(
        &sandbox,
        "curl --silent --max-time 5 http://example.com || echo BLOCKED",
    )
    .await;

    assert_eq!(stdout(&output), "BLOCKED");
}

#[tokio::test]
async fn proxy_variables_are_absent_without_network_access() {
    let sandbox = default_sandbox().await;
    let output = sh(&sandbox, "printf %s \"${HTTP_PROXY:-unset}\"").await;

    assert_eq!(stdout(&output), "unset");
    assert_eq!(sandbox.proxy_url(), None);
}

#[tokio::test]
async fn proxy_variables_are_set_when_network_access_is_configured() {
    let config = SandboxConfigBuilder::default()
        .network(heel::AllowAll)
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let output = sh(&sandbox, "printf %s \"$HTTP_PROXY\"").await;

    assert_eq!(stdout(&output), sandbox.proxy_url().expect("proxy runs"));
}

#[tokio::test]
async fn file_size_limits_are_enforced() {
    let config = SandboxConfigBuilder::default()
        .limits(
            heel::ResourceLimits::builder()
                .max_file_size_bytes(1024)
                .build(),
        )
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    // Well under the limit.
    let small = sh(
        &sandbox,
        "dd if=/dev/zero of=small bs=512 count=1 2>/dev/null",
    )
    .await;
    assert!(small.status.success(), "a small write must succeed");

    // Well over it: the kernel raises SIGXFSZ or returns EFBIG.
    let large = sh(
        &sandbox,
        "dd if=/dev/zero of=large bs=1024 count=64 2>/dev/null",
    )
    .await;
    assert!(!large.status.success(), "a write past the limit must fail");

    let size = std::fs::metadata(sandbox.working_dir().join("large"))
        .map(|meta| meta.len())
        .unwrap_or(0);
    assert!(size <= 1024, "wrote {size} bytes past a 1024 byte limit");
}

#[tokio::test]
async fn the_working_directory_is_removed_when_the_sandbox_is_dropped() {
    let sandbox = default_sandbox().await;
    let path = sandbox.working_dir().to_path_buf();

    sh(&sandbox, "echo data > file.txt").await;
    assert!(path.join("file.txt").exists());

    drop(sandbox);
    assert!(!path.exists(), "the working directory must be removed");
}

#[tokio::test]
async fn spawned_processes_are_killed_when_the_sandbox_is_dropped() {
    let sandbox = default_sandbox().await;
    let child = sandbox
        .command("/bin/sh")
        .arg("-c")
        .arg("sleep 300")
        .spawn()
        .await
        .expect("spawns");
    let pid = child.id() as i32;

    // SAFETY: signal 0 only checks whether the PID can be signalled.
    let alive = unsafe { libc::kill(pid, 0) };
    assert_eq!(alive, 0, "the child must be running");

    drop(child);
    drop(sandbox);

    // SIGKILL is delivered synchronously during drop, and the child is reaped,
    // so the PID is gone by the time drop returns.
    // SAFETY: signal 0 only checks whether the PID can be signalled.
    let alive = unsafe { libc::kill(pid, 0) };
    assert_eq!(alive, -1, "the child must not outlive the sandbox");
}

#[tokio::test]
async fn exit_codes_are_reported_faithfully() {
    let sandbox = default_sandbox().await;

    let output = sh(&sandbox, "exit 42").await;
    assert_eq!(output.status.code(), Some(42));
}

#[tokio::test]
async fn a_missing_configured_path_is_an_error_rather_than_a_silent_denial() {
    let config = SandboxConfigBuilder::default()
        .readable_path("/definitely/not/a/real/path")
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let error = sandbox
        .command("/bin/echo")
        .arg("hello")
        .output()
        .await
        .expect_err("a path that cannot be granted must fail");

    assert!(
        error.to_string().contains("/definitely/not/a/real/path"),
        "the error must name the path: {error}"
    );
}
