use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

use super::protocol::{IpcError, IpcRequest, IpcResponse, MAX_FRAME_BYTES};
use super::server::IpcDispatcher;

/// A trusted TCP IPC peer resolved before sandbox execution.
#[derive(Debug, Clone, Copy)]
pub struct TcpIpcEndpoint {
    address: SocketAddr,
    timeout: Duration,
}

impl TcpIpcEndpoint {
    /// Use an explicit peer and deadline for connecting and serving a request.
    pub fn new(address: SocketAddr, timeout: Duration) -> Self {
        Self { address, timeout }
    }

    /// Resolve a `tcp://host:port` URI outside the sandbox.
    pub async fn resolve(value: &str, timeout: Duration) -> Result<Self, IpcError> {
        let uri: http::Uri = value.parse().map_err(|error| {
            IpcError::InvalidProtocol(format!("invalid TCP IPC endpoint: {error}"))
        })?;
        let authority = uri.authority().ok_or_else(|| {
            IpcError::InvalidProtocol("TCP IPC endpoint requires a host and port".into())
        })?;
        if uri.scheme_str() != Some("tcp")
            || authority.as_str().contains('@')
            || uri
                .path_and_query()
                .is_some_and(|path| !path.as_str().is_empty() && path.as_str() != "/")
        {
            return Err(IpcError::InvalidProtocol(
                "expected tcp://host:port without credentials or a path".into(),
            ));
        }
        let port = authority
            .port_u16()
            .filter(|port| *port != 0)
            .ok_or_else(|| {
                IpcError::InvalidProtocol("TCP IPC endpoint requires a nonzero port".into())
            })?;
        let host = authority.host().trim_matches(['[', ']']).to_owned();
        let address = blocking::unblock(move || {
            (host.as_str(), port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "IPC host resolved to no addresses",
                    )
                })
        })
        .await?;
        Ok(Self::new(address, timeout))
    }

    /// The resolved, immutable destination.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The deadline for one connection and request.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    async fn request(&self, method: &str, params: &[u8]) -> Result<Vec<u8>, IpcError> {
        let operation = async {
            let mut stream = async_net::TcpStream::connect(self.address).await?;
            stream.set_nodelay(true)?;
            stream
                .write_all(&IpcRequest::encode(method, params)?)
                .await?;
            let mut length = [0; 4];
            stream.read_exact(&mut length).await?;
            let length = u32::from_be_bytes(length) as usize;
            if length == 0 || length > MAX_FRAME_BYTES {
                return Err(IpcError::InvalidProtocol(format!(
                    "invalid IPC response length: {length}"
                )));
            }
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await?;
            let response = IpcResponse::decode(&body)?;
            if response.success {
                Ok(response.payload)
            } else {
                Err(IpcError::Remote(rmp_serde::from_slice(&response.payload)?))
            }
        };
        futures_lite::future::race(operation, async {
            smol::Timer::after(self.timeout).await;
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP IPC request deadline exceeded",
            )
            .into())
        })
        .await
    }
}

impl IpcDispatcher for TcpIpcEndpoint {
    async fn handle(&self, method: &str, params: Vec<u8>) -> Result<Vec<u8>, IpcError> {
        self.request(method, &params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn endpoint_resolution_rejects_non_ipc_uris() {
        for value in [
            "http://127.0.0.1:8000",
            "tcp://127.0.0.1",
            "tcp://127.0.0.1:0",
            "tcp://user@127.0.0.1:8000",
            "tcp://127.0.0.1:8000/path",
            "tcp://127.0.0.1:8000/?query=1",
        ] {
            assert!(
                matches!(
                    TcpIpcEndpoint::resolve(value, Duration::from_secs(1)).await,
                    Err(IpcError::InvalidProtocol(_))
                ),
                "accepted {value}"
            );
        }
    }

    #[tokio::test]
    async fn endpoint_resolution_preserves_ipv6_and_the_request_deadline() {
        let timeout = Duration::from_secs(7);
        let endpoint = TcpIpcEndpoint::resolve("tcp://[::1]:4567", timeout)
            .await
            .expect("resolves");
        assert_eq!(endpoint.address(), "[::1]:4567".parse().expect("address"));
        assert_eq!(endpoint.timeout(), timeout);
    }

    #[tokio::test]
    async fn a_peer_that_never_replies_is_bounded_by_the_deadline() {
        let listener = async_net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let endpoint = TcpIpcEndpoint::new(
            listener.local_addr().expect("address"),
            Duration::from_millis(25),
        );
        let peer = async {
            let (_stream, _) = listener.accept().await.expect("accepts");
            smol::Timer::after(Duration::from_millis(100)).await;
        };
        let (_, result) = futures_lite::future::zip(peer, endpoint.request("probe", &[])).await;
        assert!(
            matches!(result, Err(IpcError::Io(ref error)) if error.kind() == std::io::ErrorKind::TimedOut)
        );
    }
}
