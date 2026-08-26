//! Network proxy for filtering sandboxed process network access
//!
//! This module implements a local HTTP/HTTPS proxy that intercepts network
//! requests from sandboxed processes and applies [`NetworkPolicy`] filtering.
//! The platform backend restricts sandboxed processes to connecting to this
//! proxy, so every outbound connection is subject to the policy.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_net::{TcpListener, TcpStream};
use bytes::Bytes;
use executor_core::{Executor, Task};
use futures_lite::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue};
use hyper::rt::Executor as HyperExecutor;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use smol_hyper::rt::FuturesIo;

use crate::accept::{ShutdownSignal, accept_loop};
use crate::error::{Error, Result};
use crate::network::{DomainRequest, NetworkPolicy};

/// A response body carrying either a static message or an upstream body.
type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// A local HTTP proxy that applies a [`NetworkPolicy`] to every request.
pub struct NetworkProxy<N: NetworkPolicy> {
    addr: SocketAddr,
    shutdown: ShutdownSignal,
    _policy: std::marker::PhantomData<fn() -> N>,
}

impl<N: NetworkPolicy> NetworkProxy<N> {
    /// Bind the proxy on loopback and start serving.
    ///
    /// This is internal - [`Sandbox`](crate::Sandbox) provides the executor.
    pub(crate) async fn new<E: Executor + Clone + 'static>(policy: N, executor: E) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (shutdown, shutdown_rx) = ShutdownSignal::new();

        tracing::debug!(%addr, "network proxy: bound");

        let policy = Arc::new(policy);
        let accept_executor = executor.clone();
        executor
            .spawn(async move {
                accept_loop(
                    listener.incoming(),
                    shutdown_rx,
                    "network proxy",
                    |stream| {
                        let policy = Arc::clone(&policy);
                        let executor = accept_executor.clone();
                        accept_executor
                            .spawn(async move {
                                if let Err(error) =
                                    handle_connection(stream, policy, executor).await
                                {
                                    tracing::warn!(%error, "network proxy: connection error");
                                }
                            })
                            .detach();
                    },
                )
                .await;
            })
            .detach();

        Ok(Self {
            addr,
            shutdown,
            _policy: std::marker::PhantomData,
        })
    }

    /// The address the proxy is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The proxy URL to publish as `HTTP_PROXY`/`HTTPS_PROXY`.
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stop accepting new connections.
    pub fn stop(&self) {
        self.shutdown.stop();
    }
}

/// Wrapper for the executor to implement [`hyper::rt::Executor`].
struct ExecutorWrapper<E>(Arc<E>);

impl<E> ExecutorWrapper<E> {
    fn new(executor: E) -> Self {
        Self(Arc::new(executor))
    }
}

impl<E> Clone for ExecutorWrapper<E> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<Fut, E> HyperExecutor<Fut> for ExecutorWrapper<E>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
    E: Executor + 'static,
{
    fn execute(&self, fut: Fut) {
        self.0.spawn(fut).detach();
    }
}

/// Serve one client connection.
async fn handle_connection<N: NetworkPolicy, E: Executor + 'static>(
    stream: TcpStream,
    policy: Arc<N>,
    executor: E,
) -> Result<()> {
    let io = FuturesIo::new(stream);
    let hyper_executor = ExecutorWrapper::new(executor);

    http1::Builder::new()
        .keep_alive(false)
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(move |req| {
                let policy = Arc::clone(&policy);
                let executor = hyper_executor.clone();
                async move { Ok::<_, hyper::Error>(proxy_request(req, policy, executor).await) }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| Error::Proxy(e.to_string()))
}

/// Route a request to the CONNECT or plain-HTTP handler.
async fn proxy_request<N: NetworkPolicy, E: Executor + 'static>(
    req: Request<Incoming>,
    policy: Arc<N>,
    executor: ExecutorWrapper<E>,
) -> Response<ProxyBody> {
    tracing::debug!(method = %req.method(), uri = %req.uri(), "network proxy: request");

    if req.method() == Method::CONNECT {
        handle_connect(req, policy, executor).await
    } else {
        handle_http(req, policy, executor).await
    }
}

/// Tunnel an HTTPS connection after checking the policy.
async fn handle_connect<N: NetworkPolicy, E: Executor + 'static>(
    req: Request<Incoming>,
    policy: Arc<N>,
    executor: ExecutorWrapper<E>,
) -> Response<ProxyBody> {
    let Some(authority) = req.uri().authority() else {
        return error_response(StatusCode::BAD_REQUEST, "Missing CONNECT authority");
    };

    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    if host.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Invalid CONNECT authority");
    }

    let request = DomainRequest::new(&host, port);
    if !policy.check(&request).await {
        tracing::info!(host = %request.host(), port, "network proxy: CONNECT denied by policy");
        return error_response(StatusCode::FORBIDDEN, "Blocked by sandbox policy");
    }

    // Establish the upstream connection before reporting success, so that a
    // failure to reach the target is reported as a failure rather than as an
    // established tunnel that immediately closes.
    let target = match connect_target(request.host(), port).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(host = %request.host(), port, %error, "network proxy: connect failed");
            return error_response(StatusCode::BAD_GATEWAY, "Failed to connect to target");
        }
    };

    tracing::debug!(host = %request.host(), port, "network proxy: tunnel established");

    executor.execute(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(error) = tunnel(upgraded, target).await {
                    tracing::warn!(%error, "network proxy: tunnel error");
                }
            }
            Err(error) => tracing::warn!(%error, "network proxy: upgrade error"),
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .expect("status-only response always builds")
}

/// Forward a plain HTTP request after checking the policy.
async fn handle_http<N: NetworkPolicy, E: Executor + 'static>(
    req: Request<Incoming>,
    policy: Arc<N>,
    executor: ExecutorWrapper<E>,
) -> Response<ProxyBody> {
    let uri = req.uri();
    let Some(host) = uri
        .host()
        .filter(|host| !host.is_empty())
        .map(str::to_string)
    else {
        // A proxied request must carry an absolute URI; without a host there is
        // nothing to check a policy against and nothing to connect to.
        return error_response(StatusCode::BAD_REQUEST, "Missing request host");
    };
    let port = uri.port_u16().unwrap_or(80);

    let request = DomainRequest::new(&host, port);
    if !policy.check(&request).await {
        tracing::info!(host = %request.host(), port, "network proxy: request denied by policy");
        return error_response(StatusCode::FORBIDDEN, "Blocked by sandbox policy");
    }

    tracing::debug!(host = %request.host(), port, path = %uri.path(), "network proxy: request allowed");

    let target = match connect_target(request.host(), port).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(host = %request.host(), port, %error, "network proxy: connect failed");
            return error_response(StatusCode::BAD_GATEWAY, "Failed to connect to target");
        }
    };

    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake(FuturesIo::new(target)).await {
            Ok(parts) => parts,
            Err(error) => {
                tracing::warn!(%error, "network proxy: handshake error");
                return error_response(StatusCode::BAD_GATEWAY, "Handshake failed");
            }
        };

    executor.execute(async move {
        if let Err(error) = conn.await {
            tracing::warn!(%error, "network proxy: connection driver error");
        }
    });

    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let mut forward = Request::builder()
        .method(req.method())
        .uri(path)
        .version(req.version());

    for (name, value) in end_to_end_headers(req.headers()) {
        forward = forward.header(name, value);
    }
    forward = forward.header(CONNECTION, close_header_value());

    let forward = match forward.body(req.into_body()) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(%error, "network proxy: request build error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Request build error");
        }
    };

    match sender.send_request(forward).await {
        Ok(response) => rewrite_proxy_response(response),
        Err(error) => {
            tracing::warn!(%error, "network proxy: forward error");
            error_response(StatusCode::BAD_GATEWAY, "Forward failed")
        }
    }
}

/// Resolve and connect to an upstream target.
///
/// Addresses local to the host running the sandbox are refused: the sandbox
/// grants the proxy full network access, so forwarding to loopback or
/// link-local addresses would let sandboxed code reach services that the
/// platform backend denies it directly.
async fn connect_target(host: &str, port: u16) -> io::Result<TcpStream> {
    let addrs = async_net::resolve((host, port)).await?;
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses for {host}:{port}"),
        ));
    }

    let mut last_error = None;
    for addr in addrs {
        if is_host_local(addr.ip()) {
            tracing::warn!(%host, %addr, "network proxy: refusing host-local target");
            last_error = Some(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{addr} is local to the sandbox host"),
            ));
            continue;
        }
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.expect("non-empty address list yields an error or a stream"))
}

/// Whether an address belongs to the machine hosting the sandbox.
fn is_host_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() || ip.is_broadcast()
        }
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unspecified(),
    }
}

/// Copy an upstream response, dropping hop-by-hop headers.
fn rewrite_proxy_response(response: Response<Incoming>) -> Response<ProxyBody> {
    let (parts, body) = response.into_parts();
    let mut builder = Response::builder()
        .status(parts.status)
        .version(parts.version);

    for (name, value) in end_to_end_headers(&parts.headers) {
        builder = builder.header(name, value);
    }

    builder = builder.header(CONNECTION, close_header_value());

    builder.body(body.boxed()).unwrap_or_else(|error| {
        tracing::warn!(%error, "network proxy: response build error");
        error_response(StatusCode::BAD_GATEWAY, "Response build error")
    })
}

/// Build a status-and-message response.
fn error_response(status: StatusCode, message: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(full_body(message))
        .expect("static error response must build")
}

/// The headers that may be forwarded across a proxy hop.
fn end_to_end_headers(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    let connection_scoped = connection_scoped_headers(headers);
    headers
        .iter()
        .filter(|(name, _)| !is_hop_by_hop_header(name, &connection_scoped))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Headers named by the `Connection` header, which are hop-by-hop by definition.
fn connection_scoped_headers(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
}

fn is_hop_by_hop_header(name: &HeaderName, connection_scoped: &[HeaderName]) -> bool {
    if connection_scoped.iter().any(|candidate| candidate == name) {
        return true;
    }

    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn close_header_value() -> HeaderValue {
    HeaderValue::from_static("close")
}

/// Bidirectional copy between the upgraded client connection and the target.
async fn tunnel(upgraded: hyper::upgrade::Upgraded, target: TcpStream) -> io::Result<()> {
    use futures_lite::io::split;

    let (client_read, client_write) = split(UpgradedIo(upgraded));
    let (target_read, target_write) = split(target);

    let (client_result, target_result) = futures_lite::future::zip(
        relay_and_close(client_read, target_write),
        relay_and_close(target_read, client_write),
    )
    .await;
    client_result?;
    target_result?;

    Ok(())
}

/// Copy one direction, then close the writer so the peer observes EOF.
async fn relay_and_close<R, W>(reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copy_result = futures_lite::io::copy(reader, &mut writer).await;
    let close_result = writer.close().await;
    match copy_result {
        Ok(bytes) => close_result.map(|()| bytes),
        Err(error) => Err(error),
    }
}

/// Adapts hyper's upgraded connection to the futures I/O traits used above.
struct UpgradedIo(hyper::upgrade::Upgraded);

impl AsyncRead for UpgradedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut read_buf = hyper::rt::ReadBuf::new(buf);

        match hyper::rt::Read::poll_read(Pin::new(&mut self.0), cx, read_buf.unfilled()) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UpgradedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        hyper::rt::Write::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(s: &'static str) -> ProxyBody {
    Full::new(Bytes::from(s))
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::AllowAll;
    use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
    use hyper::header::{CONTENT_TYPE, HOST};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    #[test]
    fn host_local_addresses_are_refused() {
        assert!(is_host_local(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_host_local(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_host_local(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_host_local(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_host_local(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!is_host_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn end_to_end_headers_drops_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("example.com"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, x-trace-id"),
        );
        headers.insert(
            HeaderName::from_static("x-trace-id"),
            HeaderValue::from_static("abc123"),
        );
        headers.insert(
            HeaderName::from_static("proxy-connection"),
            HeaderValue::from_static("keep-alive"),
        );
        headers.insert(
            HeaderName::from_static("te"),
            HeaderValue::from_static("trailers"),
        );

        let filtered = end_to_end_headers(&headers);

        assert!(filtered.iter().any(|(name, _)| name == HOST));
        assert!(filtered.iter().any(|(name, _)| name == CONTENT_TYPE));
        assert!(!filtered.iter().any(|(name, _)| name == CONNECTION));
        assert!(
            !filtered
                .iter()
                .any(|(name, _)| name.as_str() == "x-trace-id")
        );
        assert!(
            !filtered
                .iter()
                .any(|(name, _)| name.as_str() == "proxy-connection")
        );
        assert!(!filtered.iter().any(|(name, _)| name.as_str() == "te"));
    }

    #[tokio::test]
    async fn connect_to_host_local_target_is_refused() {
        // A listener on loopback stands in for any host-local service the
        // sandbox must not reach through the proxy.
        let target = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let target_addr = target.local_addr().expect("has an address");

        let proxy = NetworkProxy::new(AllowAll, executor_core::tokio::TokioGlobal)
            .await
            .expect("proxy starts");
        let mut client = TcpStream::connect(proxy.addr()).await.expect("connects");
        let request = format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n");
        client
            .write_all(request.as_bytes())
            .await
            .expect("writes CONNECT");

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .expect("proxy answers")
            .expect("reads response");
        assert!(
            response.starts_with(b"HTTP/1.1 502"),
            "expected 502, got {}",
            String::from_utf8_lossy(&response)
        );
    }

    #[tokio::test]
    async fn connect_tunnel_propagates_client_half_close() {
        use std::net::Shutdown;

        let target_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("target listener binds");
        let target_addr = target_listener
            .local_addr()
            .expect("target listener has an address");
        let target = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.expect("target accepts");
            let mut request = Vec::new();
            stream
                .read_to_end(&mut request)
                .await
                .expect("target reads through client EOF");
            assert_eq!(request, b"ping");
            stream
                .write_all(b"pong")
                .await
                .expect("target writes response");
        });

        // The host-local guard applies to the proxy's own forwarding, so this
        // test drives the tunnel directly rather than through `connect_target`.
        let upstream = TcpStream::connect(target_addr).await.expect("connects");
        let (mut client, server) = duplex_pair().await;
        let tunnel_task = tokio::spawn(async move {
            let (client_read, client_write) = futures_lite::io::split(server);
            let (target_read, target_write) = futures_lite::io::split(upstream);
            let _ = futures_lite::future::zip(
                relay_and_close(client_read, target_write),
                relay_and_close(target_read, client_write),
            )
            .await;
        });

        client.write_all(b"ping").await.expect("writes request");
        client
            .shutdown(Shutdown::Write)
            .expect("client half-closes write side");

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .expect("EOF must propagate to the target")
            .expect("reads tunneled response");
        assert_eq!(response, b"pong");

        target.await.expect("target task completes");
        tunnel_task.await.expect("tunnel task completes");
    }

    /// A connected pair of loopback sockets.
    async fn duplex_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        let connect = TcpStream::connect(addr);
        let accept = async { listener.accept().await.map(|(stream, _)| stream) };
        let (client, server) = futures_lite::future::zip(connect, accept).await;
        (client.expect("connects"), server.expect("accepts"))
    }
}
