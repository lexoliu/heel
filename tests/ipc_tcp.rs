#![doc = "External TCP IPC is relayed through a protected local socket without child TCP access."]

use std::borrow::Cow;
use std::time::Duration;

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use heel::ipc::{IpcCommand, IpcRouter, TcpIpcEndpoint};
use heel::{Sandbox, SandboxConfigBuilder};
use serde::Deserialize;

struct Echo;

#[derive(Deserialize)]
struct EchoArgs {
    message: String,
}

impl IpcCommand for Echo {
    fn name(&self) -> Cow<'static, str> {
        "echo".into()
    }

    type Args = EchoArgs;
    type Response = String;

    fn handle(&self, args: EchoArgs) -> impl std::future::Future<Output = String> {
        std::future::ready(args.message)
    }
}

#[tokio::test]
async fn external_ipc_reaches_the_live_handler_without_opening_child_tcp() {
    let listener = async_net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = listener.local_addr().expect("address");
    let router = IpcRouter::new().register(Echo);
    let sandbox = Sandbox::with_config_and_executor(
        SandboxConfigBuilder::default()
            .external_ipc(TcpIpcEndpoint::new(address, Duration::from_secs(5)))
            .heel_binary(env!("CARGO_BIN_EXE_heel"))
            .build(),
        executor_core::tokio::TokioGlobal,
    )
    .await
    .expect("sandbox starts");
    let server = async {
        let (mut stream, _) = listener.accept().await.expect("accepts");
        let mut length = [0; 4];
        stream.read_exact(&mut length).await.expect("reads length");
        let mut body = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut body).await.expect("reads request");
        let request = heel::ipc::IpcRequest::decode(&body).expect("decodes request");
        let payload = router
            .handle(&request.method, request.params)
            .await
            .expect("dispatches");
        stream
            .write_all(&heel::ipc::IpcResponse::success(payload).encode())
            .await
            .expect("writes response");
    };
    let caller = async {
        sandbox
            .command(env!("CARGO_BIN_EXE_heel"))
            .args(["ipc", "echo", "--", "--message", "live-handler-ok"])
            .env("HEEL_IPC_ENDPOINT", "tcp://127.0.0.1:1")
            .output()
            .await
            .expect("client runs")
    };
    let (_, output) = futures_lite::future::zip(server, caller).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "live-handler-ok"
    );
    #[cfg(windows)]
    let curl = "curl.exe";
    #[cfg(not(windows))]
    let curl = "/usr/bin/curl";
    let uri = http::Uri::builder()
        .scheme("http")
        .authority(address.to_string())
        .path_and_query("/")
        .build()
        .expect("URI");
    let denied = sandbox
        .command(curl)
        .args([
            "--noproxy",
            "*",
            "--max-time",
            "2",
            uri.to_string().as_str(),
        ])
        .output()
        .await
        .expect("curl runs");
    assert_eq!(
        denied.status.code(),
        Some(7),
        "TCP must fail to connect, not time out after connecting: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
}
