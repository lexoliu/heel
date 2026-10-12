#![doc = "Native Windows IPC entrypoints, process resolution and argument fidelity."]
#![cfg(windows)]

use std::borrow::Cow;

use heel::ipc::{IpcCommand, IpcRouter};
use heel::{Sandbox, SandboxConfigBuilder};
use serde::Deserialize;

struct Echo;

#[derive(Deserialize)]
struct EchoArgs {
    message: String,
}

impl IpcCommand for Echo {
    fn name(&self) -> Cow<'static, str> {
        "echo-native".into()
    }

    fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[Cow::Borrowed("message")])
    }

    type Args = EchoArgs;
    type Response = String;

    fn handle(&self, args: EchoArgs) -> impl std::future::Future<Output = String> {
        std::future::ready(args.message)
    }
}

async fn sandbox() -> Sandbox {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("heel=debug")
        .try_init();
    Sandbox::with_config_and_executor(
        SandboxConfigBuilder::default()
            .ipc(IpcRouter::new().register(Echo))
            .heel_binary(env!("CARGO_BIN_EXE_heel"))
            .build(),
        executor_core::tokio::TokioGlobal,
    )
    .await
    .expect("sandbox starts")
}

#[tokio::test]
async fn native_command_resolves_through_the_sandbox_path_and_preserves_arguments() {
    let sandbox = sandbox().await;
    let message = "Unicode 中文 & %PATH% ! ^ \"quotes\"";
    let output = sandbox
        .command("echo-native")
        .arg(message)
        .output()
        .await
        .expect("native shim runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), message);
}

#[tokio::test]
async fn cmd_invokes_the_native_ipc_handler() {
    let sandbox = sandbox().await;
    let output = sandbox
        .command("cmd.exe")
        .args(["/D", "/S", "/C", "echo-native native-ipc-ok"])
        .output()
        .await
        .expect("cmd runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "native-ipc-ok"
    );
}
