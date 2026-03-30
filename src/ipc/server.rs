//! IPC server implementation
//!
//! Loopback TCP server for handling IPC requests from sandboxed processes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_net::TcpListener;
use executor_core::{Executor, Task};
use futures_lite::StreamExt;
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

use crate::ipc::protocol::{IpcError, IpcRequest, IpcResponse};
use crate::ipc::router::IpcRouter;

/// IPC server that listens on 127.0.0.1 with an ephemeral port
pub struct IpcServer {
    #[allow(dead_code)]
    router: Arc<IpcRouter>,
    addr: SocketAddr,
    endpoint: String,
    running: Arc<AtomicBool>,
}

impl IpcServer {
    /// Create and start a new IPC server
    ///
    /// # Arguments
    /// * `router` - The router to dispatch incoming requests
    /// * `executor` - Executor to spawn the server task on
    ///
    /// The server binds to 127.0.0.1 with an ephemeral port.
    pub async fn new<E: Executor + Clone + 'static>(
        router: IpcRouter,
        executor: E,
    ) -> Result<Self, IpcError> {
        let router = Arc::new(router);
        let running = Arc::new(AtomicBool::new(true));

        // Bind to loopback with an ephemeral port
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let endpoint = format!("tcp://{}", addr);

        tracing::info!(%endpoint, "IPC server started");

        // Spawn the accept loop
        let server = Self {
            router: Arc::clone(&router),
            addr,
            endpoint,
            running: Arc::clone(&running),
        };

        let router_clone = Arc::clone(&router);
        let running_clone = Arc::clone(&running);
        executor
            .spawn(run_server(
                listener,
                router_clone,
                running_clone,
                executor.clone(),
            ))
            .detach();

        Ok(server)
    }

    /// Get the listener address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get the IPC endpoint string used by clients.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Stop the server
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        tracing::debug!(endpoint = %self.endpoint, "IPC server stopping");
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Main server accept loop
async fn run_server<E: Executor + Clone + 'static>(
    listener: TcpListener,
    router: Arc<IpcRouter>,
    running: Arc<AtomicBool>,
    executor: E,
) {
    let mut incoming = listener.incoming();

    while running.load(Ordering::SeqCst) {
        let accept_result = futures_lite::future::or(async { incoming.next().await }, async {
            futures_lite::future::yield_now().await;
            async_io::Timer::after(Duration::from_millis(100)).await;
            None
        })
        .await;

        match accept_result {
            Some(Ok(stream)) => {
                let router = Arc::clone(&router);
                executor.spawn(handle_connection(stream, router)).detach();
            }
            Some(Err(e)) if running.load(Ordering::SeqCst) => {
                tracing::warn!(error = %e, "failed to accept IPC connection");
            }
            Some(Err(_)) => {}
            None => {
                // Timeout or listener closed; loop to re-check running flag
            }
        }
    }
}

/// Handle a single connection
async fn handle_connection(mut stream: async_net::TcpStream, router: Arc<IpcRouter>) {
    loop {
        // Read the length prefix (4 bytes, u32 BE)
        let mut len_buf = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut len_buf).await {
            if e.kind() != std::io::ErrorKind::UnexpectedEof {
                tracing::debug!(error = %e, "failed to read request length");
            }
            break;
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 16 * 1024 * 1024 {
            // Max 16MB
            tracing::warn!(len, "invalid request length");
            break;
        }

        // Read the request body
        let mut body = vec![0u8; len];
        if let Err(e) = stream.read_exact(&mut body).await {
            tracing::debug!(error = %e, "failed to read request body");
            break;
        }

        // Parse and handle the request
        let response = match IpcRequest::from_bytes(&body) {
            Ok(request) => {
                tracing::debug!(method = %request.method, "handling IPC request");
                match router.handle(&request.method, &request.params).await {
                    Ok(result) => IpcResponse {
                        success: true,
                        payload: result,
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "IPC handler error");
                        IpcResponse::error(&e.to_string()).unwrap_or_else(|_| IpcResponse {
                            success: false,
                            payload: vec![],
                        })
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse IPC request");
                IpcResponse::error(&e.to_string()).unwrap_or_else(|_| IpcResponse {
                    success: false,
                    payload: vec![],
                })
            }
        };

        // Send the response
        let response_bytes = response.to_bytes();
        if let Err(e) = stream.write_all(&response_bytes).await {
            tracing::debug!(error = %e, "failed to write response");
            break;
        }
    }
}
