//! Client for calling host commands from inside a sandbox.
//!
//! Sandboxed processes reach the host through the generated command shims,
//! which run `heel ipc`. That command uses this client, so the framing lives in
//! one place and is exercised by the same tests as the server.

use std::io::{Read, Write};
use std::path::Path;

use interprocess::local_socket::Stream;
use interprocess::local_socket::traits::Stream as _;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::ipc::endpoint;
use crate::ipc::protocol::{IpcError, IpcRequest, IpcResponse, MAX_FRAME_BYTES};

/// A connection to a sandbox's IPC server.
///
/// Calls are blocking: the client runs in a short-lived helper process whose
/// only job is to issue one request.
#[derive(Debug)]
pub struct IpcClient {
    stream: Stream,
}

impl IpcClient {
    /// Connect to the IPC socket at `path`.
    ///
    /// Inside a sandbox the path comes from `HEEL_IPC_ENDPOINT`.
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, IpcError> {
        Ok(Self {
            stream: Stream::connect(endpoint::name(path.as_ref())?)?,
        })
    }

    /// Call `method` with already-encoded MessagePack arguments.
    ///
    /// Returns the encoded response payload, or the error the handler reported.
    pub fn call_raw(&mut self, method: &str, params: &[u8]) -> Result<Vec<u8>, IpcError> {
        self.stream
            .write_all(&IpcRequest::encode(method, params)?)?;

        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len == 0 || len > MAX_FRAME_BYTES {
            return Err(IpcError::InvalidProtocol(format!(
                "response length {len} is outside the 1..={MAX_FRAME_BYTES} byte range"
            )));
        }

        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body)?;

        let response = IpcResponse::decode(&body)?;
        if response.success {
            return Ok(response.payload);
        }

        // A failure payload is a MessagePack string; fall back to the raw bytes
        // only so a malformed error is still reported rather than swallowed.
        let message = rmp_serde::from_slice::<String>(&response.payload)
            .unwrap_or_else(|_| String::from_utf8_lossy(&response.payload).into_owned());
        Err(IpcError::Remote(message))
    }

    /// Call `method` with typed arguments and decode the typed response.
    pub fn call<A: Serialize, R: DeserializeOwned>(
        &mut self,
        method: &str,
        args: &A,
    ) -> Result<R, IpcError> {
        let params = rmp_serde::to_vec_named(args)?;
        let payload = self.call_raw(method, &params)?;
        Ok(rmp_serde::from_slice(&payload)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcCommand, IpcRouter, IpcServer};
    use serde::Deserialize;
    use std::borrow::Cow;

    struct Sum;

    #[derive(Serialize, Deserialize)]
    struct SumArgs {
        a: i64,
        b: i64,
    }

    impl IpcCommand for Sum {
        fn name(&self) -> Cow<'static, str> {
            "sum".into()
        }

        type Args = SumArgs;
        type Response = i64;

        async fn handle(&self, args: SumArgs) -> i64 {
            args.a + args.b
        }
    }

    struct Failing;

    impl IpcCommand for Failing {
        fn name(&self) -> Cow<'static, str> {
            "failing".into()
        }

        type Args = i64;
        type Response = ();

        async fn handle(&self, _args: i64) {}
    }

    /// Start a server on a temporary socket for one test.
    async fn serve(dir: &tempfile::TempDir, router: IpcRouter) -> IpcServer {
        IpcServer::new(
            dir.path().join("ipc.sock"),
            router,
            executor_core::tokio::TokioGlobal,
        )
        .await
        .expect("server starts")
    }

    #[tokio::test]
    async fn round_trips_typed_calls() {
        let dir = tempfile::tempdir().expect("tempdir");
        let server = serve(&dir, IpcRouter::new().register(Sum)).await;
        let socket = server.socket_path().to_path_buf();

        let sum: i64 = tokio::task::spawn_blocking(move || {
            let mut client = IpcClient::connect(&socket).expect("connects");
            client.call("sum", &SumArgs { a: 2, b: 40 }).expect("calls")
        })
        .await
        .expect("client task completes");

        assert_eq!(sum, 42);
    }

    #[tokio::test]
    async fn handler_errors_surface_as_remote_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let server = serve(&dir, IpcRouter::new().register(Failing)).await;
        let socket = server.socket_path().to_path_buf();

        let error = tokio::task::spawn_blocking(move || {
            let mut client = IpcClient::connect(&socket).expect("connects");
            // `Failing` expects an integer, so a map is a decoding error.
            client
                .call::<_, ()>("failing", &serde_json::json!({ "unexpected": true }))
                .expect_err("must fail")
        })
        .await
        .expect("client task completes");

        assert!(
            matches!(error, IpcError::Remote(ref message) if message.contains("deserialization")),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn unknown_methods_surface_as_remote_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let server = serve(&dir, IpcRouter::new()).await;
        let socket = server.socket_path().to_path_buf();

        let error = tokio::task::spawn_blocking(move || {
            let mut client = IpcClient::connect(&socket).expect("connects");
            client.call_raw("nope", &[]).expect_err("must fail")
        })
        .await
        .expect("client task completes");

        assert!(matches!(error, IpcError::Remote(_)), "got {error:?}");
    }
}
