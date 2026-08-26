//! IPC server.
//!
//! The server listens on a local socket named by [`crate::ipc::endpoint`]. On
//! Unix that is a filesystem socket inside an owner-only directory, which is
//! what makes the IPC surface reachable only by processes the sandbox grants
//! access to: it is not exposed to every process on the machine the way a
//! loopback TCP port would be.
//!
//! The transport is synchronous, because that is the only local-socket
//! implementation that works on every platform without binding the crate to a
//! particular async runtime. Accepting therefore happens on one dedicated
//! thread, and each connection's reads and writes are moved onto the blocking
//! pool so the executor thread is never occupied by a syscall. Request
//! *handling* stays async: a handler may await freely.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use blocking::unblock;
use executor_core::{Executor, Task};
use interprocess::local_socket::traits::{Listener as _, Stream as _};
use interprocess::local_socket::{ListenerOptions, Stream};

use crate::accept::ShutdownSignal;
use crate::ipc::endpoint;
use crate::ipc::protocol::{IpcError, IpcRequest, IpcResponse, MAX_FRAME_BYTES};
use crate::ipc::router::IpcRouter;

/// Longest usable Unix socket path.
///
/// `sockaddr_un::sun_path` is 104 bytes on macOS and 108 on Linux, including
/// the terminating NUL. Exceeding it produces a confusing `bind` failure, so
/// the limit is checked up front with a message that names the real problem.
#[cfg(unix)]
const MAX_SOCKET_PATH_LEN: usize = 100;

/// A running IPC server.
#[derive(Debug)]
pub(crate) struct IpcServer {
    socket_path: PathBuf,
    shutdown: ShutdownSignal,
}

impl IpcServer {
    /// Bind `socket_path` and start serving `router`.
    ///
    /// The parent directory must already exist; it is expected to be the
    /// sandbox's private socket directory, which is created with owner-only
    /// permissions.
    pub(crate) async fn new<E: Executor + Clone + 'static>(
        socket_path: PathBuf,
        router: IpcRouter,
        executor: E,
    ) -> Result<Self, IpcError> {
        #[cfg(unix)]
        if socket_path.as_os_str().len() > MAX_SOCKET_PATH_LEN {
            return Err(IpcError::InvalidProtocol(format!(
                "IPC socket path is {} bytes, which exceeds the {MAX_SOCKET_PATH_LEN} byte \
                 platform limit: {}",
                socket_path.as_os_str().len(),
                socket_path.display()
            )));
        }

        // A leftover socket from a crashed run would make bind fail.
        if socket_path.exists() {
            std::fs::remove_file(&socket_path)?;
        }

        let listener = ListenerOptions::new()
            .name(endpoint::name(&socket_path)?)
            .create_sync()?;
        restrict_socket_permissions(&socket_path)?;

        let (shutdown, shutdown_rx) = ShutdownSignal::new();
        let router = Arc::new(router);
        let (connections, incoming) = async_channel::unbounded();

        // Accepting blocks and cannot be cancelled, so it gets a thread of its
        // own rather than a slot in the blocking pool, which short operations
        // elsewhere in the crate depend on staying available. The thread only
        // hands connections over: spawning is left to the dispatch task, because
        // an executor may require its own thread-local context to spawn onto and
        // this thread is not part of any runtime.
        std::thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok(stream) => {
                        // `stop` closes the channel and then connects once,
                        // purely to return this call. That connection carries no
                        // request and must not be served.
                        if shutdown_rx.is_closed() {
                            break;
                        }
                        if connections.send_blocking(stream).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, "IPC server stopped accepting");
                        break;
                    }
                }
            }
            tracing::debug!("IPC accept loop finished");
        });

        // Dropping the accept thread's sender ends this task, so shutdown needs
        // no separate signal here.
        let dispatch_executor = executor.clone();
        executor
            .spawn(async move {
                while let Ok(stream) = incoming.recv().await {
                    dispatch_executor
                        .spawn(handle_connection(stream, Arc::clone(&router)))
                        .detach();
                }
            })
            .detach();

        tracing::info!(socket = %socket_path.display(), "IPC server started");

        Ok(Self {
            socket_path,
            shutdown,
        })
    }

    /// The socket path sandboxed processes connect to.
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Stop accepting new connections.
    ///
    /// The accept thread is parked in a syscall that no flag can interrupt, so
    /// it is woken with a connection that is immediately dropped. The shutdown
    /// channel is closed first, so the thread sees the closure and exits rather
    /// than serving the wake-up as a request.
    pub(crate) fn stop(&self) {
        self.shutdown.stop();

        if let Ok(name) = endpoint::name(&self.socket_path) {
            // Failure means nothing is listening any more, which is the state
            // this call is trying to reach.
            let _ = Stream::connect(name);
        }

        tracing::debug!(socket = %self.socket_path.display(), "IPC server stopping");
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        // Order matters: the wake-up connection in `stop` needs the socket to
        // still exist, so the file is only removed afterwards.
        self.stop();
        // The socket file outlives the listener; remove it so a reused working
        // directory does not inherit a stale entry.
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Restrict the socket to its owner.
#[cfg(unix)]
fn restrict_socket_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Named pipes are not filesystem objects, so there are no permissions to set.
#[cfg(not(unix))]
fn restrict_socket_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Read one length-prefixed frame, or `None` if the peer disconnected.
fn read_frame(stream: &mut Stream) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    if let Err(error) = stream.read_exact(&mut len_buf) {
        return if error.kind() == io::ErrorKind::UnexpectedEof {
            Ok(None)
        } else {
            Err(error)
        };
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("request length {len} is outside the 1..={MAX_FRAME_BYTES} byte range"),
        ));
    }

    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Serve requests on one connection until the peer disconnects.
///
/// The stream is moved onto the blocking pool for each read and write and moved
/// back afterwards. Handing the whole connection to one long-lived blocking
/// task instead would make the async dispatch below unreachable, and wrapping it
/// in an adapter that buffers reads ahead would race the writes on the same
/// socket.
async fn handle_connection(stream: Stream, router: Arc<IpcRouter>) {
    let mut stream = stream;

    loop {
        let (returned, frame) = unblock(move || {
            let mut stream = stream;
            let frame = read_frame(&mut stream);
            (stream, frame)
        })
        .await;
        stream = returned;

        let body = match frame {
            Ok(Some(body)) => body,
            Ok(None) => break,
            Err(error) => {
                tracing::debug!(%error, "failed to read request");
                break;
            }
        };

        let response = match IpcRequest::decode(&body) {
            Ok(request) => {
                tracing::debug!(method = %request.method, "handling IPC request");
                match router.handle(&request.method, request.params).await {
                    Ok(payload) => IpcResponse::success(payload),
                    Err(error) => {
                        tracing::warn!(%error, "IPC handler error");
                        IpcResponse::error(&error.to_string())
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "failed to parse IPC request");
                IpcResponse::error(&error.to_string())
            }
        };

        let encoded = response.encode();
        let (returned, written) = unblock(move || {
            let mut stream = stream;
            let written = stream.write_all(&encoded).and_then(|()| stream.flush());
            (stream, written)
        })
        .await;
        stream = returned;

        if let Err(error) = written {
            tracing::debug!(%error, "failed to write response");
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IpcCommand;
    use serde::Deserialize;

    struct Echo;

    #[derive(Deserialize)]
    struct EchoArgs {
        message: String,
    }

    impl IpcCommand for Echo {
        const NAME: &'static str = "echo";

        type Args = EchoArgs;
        type Response = String;

        async fn handle(&self, args: EchoArgs) -> String {
            args.message
        }
    }

    /// Issue one request over a fresh connection, synchronously.
    fn round_trip(socket: &Path, method: &str, params: &[u8]) -> IpcResponse {
        let mut stream = Stream::connect(endpoint::name(socket).expect("names")).expect("connects");
        let frame = IpcRequest::encode(method, params).expect("encodes");
        stream.write_all(&frame).expect("writes");
        stream.flush().expect("flushes");

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).expect("reads length");
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).expect("reads body");
        IpcResponse::decode(&body).expect("decodes")
    }

    #[tokio::test]
    async fn serves_requests_over_a_local_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("ipc.sock");

        let server = IpcServer::new(
            socket.clone(),
            IpcRouter::new().register(Echo),
            executor_core::tokio::TokioGlobal,
        )
        .await
        .expect("server starts");

        let params =
            rmp_serde::to_vec_named(&serde_json::json!({ "message": "hi" })).expect("encodes");
        let socket = server.socket_path().to_path_buf();
        let response = tokio::task::spawn_blocking(move || round_trip(&socket, "echo", &params))
            .await
            .expect("client task completes");

        assert!(response.success);
        assert_eq!(
            rmp_serde::from_slice::<String>(&response.payload).unwrap(),
            "hi"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socket_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("ipc.sock");

        let server = IpcServer::new(
            socket.clone(),
            IpcRouter::new(),
            executor_core::tokio::TokioGlobal,
        )
        .await
        .expect("server starts");

        let mode = std::fs::metadata(server.socket_path())
            .expect("socket exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "socket must not be world-accessible");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn overlong_socket_paths_are_rejected_with_a_clear_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("x".repeat(MAX_SOCKET_PATH_LEN));

        let error = IpcServer::new(socket, IpcRouter::new(), executor_core::tokio::TokioGlobal)
            .await
            .expect_err("path is too long");
        assert!(
            error.to_string().contains("platform limit"),
            "unhelpful error: {error}"
        );
    }

    #[tokio::test]
    async fn unknown_methods_produce_an_error_response() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("ipc.sock");

        let server = IpcServer::new(
            socket.clone(),
            IpcRouter::new(),
            executor_core::tokio::TokioGlobal,
        )
        .await
        .expect("server starts");

        let socket = server.socket_path().to_path_buf();
        let response = tokio::task::spawn_blocking(move || round_trip(&socket, "missing", &[]))
            .await
            .expect("client task completes");

        assert!(!response.success);
        let message: String = rmp_serde::from_slice(&response.payload).unwrap();
        assert!(message.contains("unknown method"), "got: {message}");
    }
}
