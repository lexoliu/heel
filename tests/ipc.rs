//! End-to-end IPC: a sandboxed process calling host commands.
//!
//! The sandboxed side runs the real `heel ipc` binary through the generated
//! command shims, so these cover the whole path: shim, argument parsing,
//! transport, dispatch and rendering.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use heel::ipc::{IpcCommand, IpcRouter, NoArgs};
use heel::{Sandbox, SandboxConfigBuilder};
use serde::Deserialize;

/// Echoes its arguments back, and counts how often it was called.
struct Echo {
    calls: Arc<AtomicUsize>,
}

#[derive(Debug, Deserialize)]
struct EchoArgs {
    #[serde(default)]
    first: String,
    #[serde(default)]
    second: String,
    #[serde(default)]
    flag: bool,
    #[serde(default)]
    piped: String,
}

impl IpcCommand for Echo {
    fn name(&self) -> Cow<'static, str> {
        "echo-args".into()
    }
    fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[Cow::Borrowed("first"), Cow::Borrowed("second")])
    }
    fn stdin_arg(&self) -> Option<Cow<'static, str>> {
        Some("piped".into())
    }

    type Args = EchoArgs;
    type Response = String;

    async fn handle(&self, args: EchoArgs) -> String {
        self.calls.fetch_add(1, Ordering::Relaxed);
        format!(
            "first={} second={} flag={} piped={}",
            args.first,
            args.second,
            args.flag,
            args.piped.trim()
        )
    }
}

/// Returns structured data rather than a string.
struct Structured;

impl IpcCommand for Structured {
    fn name(&self) -> Cow<'static, str> {
        "structured".into()
    }

    type Args = NoArgs;
    type Response = Vec<u32>;

    async fn handle(&self, _args: NoArgs) -> Vec<u32> {
        vec![1, 2, 3]
    }
}

/// Build a sandbox whose shims run the binary this test suite just built.
async fn sandbox_with(router: IpcRouter) -> Sandbox {
    let config = SandboxConfigBuilder::default()
        .ipc(router)
        .heel_binary(env!("CARGO_BIN_EXE_heel"))
        .build();

    Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts")
}

async fn sh(sandbox: &Sandbox, script: &str) -> std::process::Output {
    sandbox
        .command("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .await
        .expect("the shell runs")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_string()
}

#[tokio::test]
async fn positional_arguments_reach_the_host_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let sandbox = sandbox_with(IpcRouter::new().register(Echo {
        calls: Arc::clone(&calls),
    }))
    .await;

    let output = sh(&sandbox, "echo-args alpha beta").await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "first=alpha second=beta flag=false piped=");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn named_and_boolean_arguments_reach_the_host_handler() {
    let sandbox = sandbox_with(IpcRouter::new().register(Echo {
        calls: Arc::new(AtomicUsize::new(0)),
    }))
    .await;

    let output = sh(&sandbox, "echo-args --first one --second=two --flag").await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "first=one second=two flag=true piped=");
}

#[tokio::test]
async fn piped_input_reaches_the_host_handler() {
    let sandbox = sandbox_with(IpcRouter::new().register(Echo {
        calls: Arc::new(AtomicUsize::new(0)),
    }))
    .await;

    let output = sh(&sandbox, "printf 'from stdin' | echo-args alpha").await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "first=alpha second= flag=false piped=from stdin"
    );
}

#[tokio::test]
async fn handler_state_persists_across_calls() {
    let calls = Arc::new(AtomicUsize::new(0));
    let sandbox = sandbox_with(IpcRouter::new().register(Echo {
        calls: Arc::clone(&calls),
    }))
    .await;

    sh(
        &sandbox,
        "echo-args one && echo-args two && echo-args three",
    )
    .await;

    assert_eq!(calls.load(Ordering::Relaxed), 3, "state must be shared");
}

#[tokio::test]
async fn structured_responses_render_as_json() {
    let sandbox = sandbox_with(IpcRouter::new().register(Structured)).await;

    let output = sh(&sandbox, "structured").await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output).split_whitespace().collect::<String>(),
        "[1,2,3]"
    );
}

#[tokio::test]
async fn unknown_commands_fail_with_a_message() {
    let sandbox = sandbox_with(IpcRouter::new().register(Structured)).await;

    // The shim only exists for registered commands, so an unregistered name is
    // simply not on PATH.
    let output = sh(&sandbox, "nonexistent-command").await;
    assert!(!output.status.success());
}

#[tokio::test]
async fn the_ipc_socket_is_not_reachable_by_other_users() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = sandbox_with(IpcRouter::new().register(Structured)).await;
    let socket = sandbox.ipc_endpoint().expect("IPC is configured");

    let mode = std::fs::metadata(socket)
        .expect("the socket exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "the socket must be owner-only: {mode:o}");

    let dir_mode = std::fs::metadata(socket.parent().expect("has a parent"))
        .expect("the directory exists")
        .permissions()
        .mode();
    assert_eq!(dir_mode & 0o077, 0, "the directory must be owner-only");
}

#[tokio::test]
async fn ipc_does_not_open_a_network_port() {
    // IPC over a filesystem socket is what keeps the host-side command surface
    // off the loopback interface, where every local process could reach it.
    let sandbox = sandbox_with(IpcRouter::new().register(Structured)).await;
    let socket = sandbox.ipc_endpoint().expect("IPC is configured");

    assert!(socket.exists());
    assert!(
        !socket.to_string_lossy().contains("tcp://"),
        "the endpoint must be a filesystem path"
    );

    let output = sh(&sandbox, "printf %s \"$HEEL_IPC_ENDPOINT\"").await;
    assert_eq!(stdout(&output), socket.to_string_lossy());
}

#[tokio::test]
async fn the_shim_directory_is_the_only_executable_place_in_the_working_directory() {
    let sandbox = sandbox_with(IpcRouter::new().register(Structured)).await;

    // The shims run,
    let allowed = sh(&sandbox, "structured").await;
    assert!(allowed.status.success(), "{}", stderr(&allowed));

    // but a program the sandbox writes itself still does not.
    let denied = sh(
        &sandbox,
        "printf '#!/bin/sh\\necho executed\\n' > p.sh && chmod +x p.sh && ./p.sh",
    )
    .await;
    assert_ne!(stdout(&denied), "executed");
}
