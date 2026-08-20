//! Network proxy for filtering sandboxed process network access
//!
//! This module implements a local HTTP/HTTPS proxy that intercepts network
//! requests from sandboxed processes and applies NetworkPolicy filtering.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use async_net::{TcpListener, TcpStream};
use bytes::Bytes;
use executor_core::{Executor, Task};
use futures_lite::StreamExt;
use futures_lite::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue};
use hyper::rt::Executor as HyperExecutor;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};

use crate::error::{Error, Result};
use crate::network::{ConnectionDirection, DomainRequest, NetworkPolicy};

/// A network proxy that filters requests based on a NetworkPolicy
pub struct NetworkProxy<N: NetworkPolicy> {
    #[allow(dead_code)]
    policy: Arc<N>,
    addr: SocketAddr,
    running: Arc<AtomicBool>,
}

impl<N: NetworkPolicy + 'static> NetworkProxy<N> {
    /// Create a new network proxy with the given policy and executor
    ///
    /// This is internal - Sandbox provides the executor.
    pub(crate) async fn new<E: Executor + Clone + 'static>(policy: N, executor: E) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        tracing::debug!(addr = %addr, "network proxy: bound to address");

        let policy = Arc::new(policy);
        let running = Arc::new(AtomicBool::new(true));

        // Spawn the accept loop
        let policy_clone = Arc::clone(&policy);
        let running_clone = Arc::clone(&running);

        executor
            .spawn(run_proxy(
                listener,
                policy_clone,
                running_clone,
                executor.clone(),
            ))
            .detach();

        tracing::debug!("network proxy: started");

        Ok(Self {
            policy,
            addr,
            running,
        })
    }

    /// Get the proxy address (for setting HTTP_PROXY/HTTPS_PROXY)
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get the proxy URL for environment variables
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stop the proxy server
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl<N: NetworkPolicy> Drop for NetworkProxy<N> {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Wrapper for executor to implement hyper::rt::Executor
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

/// Wrapper for AsyncRead + AsyncWrite to implement hyper::rt::Read/Write
struct ConnectionWrapper<C>(C);

impl<C: Unpin + AsyncRead> hyper::rt::Read for ConnectionWrapper<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let inner = &mut self.get_mut().0;

        // SAFETY: `buf.as_mut()` gives us a `&mut [MaybeUninit<u8>]`.
        // We cast it to `&mut [u8]` and guarantee we will only write `n` bytes and call `advance(n)`
        let buffer = unsafe { &mut *(ptr::from_mut(buf.as_mut()) as *mut [u8]) };

        match Pin::new(inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(n)) => {
                // SAFETY: we just wrote `n` bytes into `buffer`, must now advance `n`
                unsafe {
                    buf.advance(n);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<C: Unpin + AsyncWrite> hyper::rt::Write for ConnectionWrapper<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_close(cx)
    }
}

/// Run the proxy server accept loop
async fn run_proxy<N: NetworkPolicy + 'static, E: Executor + Clone + 'static>(
    listener: TcpListener,
    policy: Arc<N>,
    running: Arc<AtomicBool>,
    executor: E,
) {
    let mut incoming = listener.incoming();

    while running.load(Ordering::SeqCst) {
        let accept_result = futures_lite::future::or(async { incoming.next().await }, async {
            futures_lite::future::yield_now().await;
            async_io::Timer::after(std::time::Duration::from_millis(100)).await;
            None
        })
        .await;

        match accept_result {
            Some(Ok(stream)) => {
                let peer_addr = stream.peer_addr().ok();
                let policy = Arc::clone(&policy);
                let exec = executor.clone();

                executor
                    .spawn(async move {
                        if let Err(e) = handle_connection(stream, peer_addr, policy, exec).await {
                            tracing::warn!(error = %e, "network proxy: connection error");
                        }
                    })
                    .detach();
            }
            Some(Err(e)) if running.load(Ordering::SeqCst) => {
                tracing::error!(error = %e, "network proxy: accept error");
            }
            Some(Err(_)) => {}
            None => {
                // Timeout, continue loop to check running flag
            }
        }
    }

    tracing::debug!("network proxy: stopped");
}

/// Handle a single proxy connection
async fn handle_connection<N: NetworkPolicy + 'static, E: Executor + 'static>(
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
    policy: Arc<N>,
    executor: E,
) -> Result<()> {
    let io = ConnectionWrapper(stream);
    let hyper_executor = ExecutorWrapper::new(executor);

    http1::Builder::new()
        .keep_alive(false)
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(move |req| {
                let policy = Arc::clone(&policy);
                let exec = hyper_executor.clone();
                async move { proxy_request(req, peer_addr, policy, exec).await }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| Error::ProxyError(e.to_string()))
}

/// Process a proxy request
async fn proxy_request<N: NetworkPolicy, E: Executor + 'static>(
    req: Request<Incoming>,
    peer_addr: Option<SocketAddr>,
    policy: Arc<N>,
    executor: ExecutorWrapper<E>,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    tracing::debug!(
        method = %req.method(),
        uri = %req.uri(),
        peer = ?peer_addr,
        "network proxy: request"
    );

    if req.method() == Method::CONNECT {
        handle_connect(req, policy, executor).await
    } else {
        handle_http(req, policy, executor).await
    }
}

/// Handle CONNECT method for HTTPS tunneling
async fn handle_connect<N: NetworkPolicy, E: Executor + 'static>(
    req: Request<Incoming>,
    policy: Arc<N>,
    executor: ExecutorWrapper<E>,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let authority = match req.uri().authority() {
        Some(authority) => authority,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full_body("Missing CONNECT authority"))
                .unwrap());
        }
    };

    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    if host.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(full_body("Invalid CONNECT authority"))
            .unwrap());
    }

    // Check policy
    let domain_req = DomainRequest::new(host.clone(), port, ConnectionDirection::Outbound, 0);
    let allowed = policy.check(&domain_req).await;

    if !allowed {
        tracing::info!(host = %host, port = port, "network proxy: connection denied by policy");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(full_body("Blocked by sandbox policy"))
            .unwrap());
    }

    tracing::debug!(host = %host, port = port, "network proxy: connection allowed");

    // Spawn a task to handle the tunnel after upgrade
    let target_addr = format_target_addr(&host, port);

    executor.execute(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                match TcpStream::connect(&target_addr).await {
                    Ok(target_stream) => {
                        if let Err(e) = tunnel(upgraded, target_stream).await {
                            tracing::warn!(error = %e, "network proxy: tunnel error");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(target = %target_addr, error = %e, "network proxy: failed to connect");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "network proxy: upgrade error");
            }
        }
    });

    // Return 200 Connection Established
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .unwrap())
}

/// Handle regular HTTP request
async fn handle_http<N: NetworkPolicy, E: Executor + 'static>(
    req: Request<Incoming>,
    policy: Arc<N>,
    executor: ExecutorWrapper<E>,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let uri = req.uri();
    let host = uri.host().unwrap_or_default().to_string();
    let port = uri.port_u16().unwrap_or(80);

    // Check policy
    let domain_req = DomainRequest::new(host.clone(), port, ConnectionDirection::Outbound, 0);
    let allowed = policy.check(&domain_req).await;

    if !allowed {
        tracing::info!(host = %host, port = port, "network proxy: HTTP request denied by policy");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(full_body("Blocked by sandbox policy"))
            .unwrap());
    }

    tracing::debug!(host = %host, port = port, path = %uri.path(), "network proxy: HTTP request allowed");

    // Connect to target and forward request
    let target_addr = format_target_addr(&host, port);
    let target_stream = match TcpStream::connect(&target_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target = %target_addr, error = %e, "network proxy: failed to connect");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body("Failed to connect to target"))
                .unwrap());
        }
    };

    let io = ConnectionWrapper(target_stream);

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(parts) => parts,
        Err(e) => {
            tracing::warn!(error = %e, "network proxy: handshake error");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body("Handshake failed"))
                .unwrap());
        }
    };

    // Spawn connection driver
    executor.execute(async move {
        if let Err(e) = conn.await {
            tracing::warn!(error = %e, "network proxy: connection driver error");
        }
    });

    // Build the request to forward
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let mut forward_req = Request::builder()
        .method(req.method())
        .uri(path)
        .version(req.version());

    for (name, value) in filtered_end_to_end_headers(req.headers()) {
        forward_req = forward_req.header(name, value);
    }
    forward_req = forward_req.header(CONNECTION, close_header_value());

    let forward_req = match forward_req.body(req.into_body()) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(error = %e, "network proxy: request build error");
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full_body("Request build error"))
                .unwrap());
        }
    };

    match sender.send_request(forward_req).await {
        Ok(response) => Ok(rewrite_proxy_response(response)),
        Err(e) => {
            tracing::warn!(error = %e, "network proxy: forward error");
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body("Forward failed"))
                .unwrap())
        }
    }
}

fn rewrite_proxy_response(response: Response<Incoming>) -> Response<BoxBody<Bytes, hyper::Error>> {
    let (parts, body) = response.into_parts();
    let mut builder = Response::builder()
        .status(parts.status)
        .version(parts.version);

    for (name, value) in filtered_end_to_end_headers(&parts.headers) {
        builder = builder.header(name, value);
    }

    builder = builder.header(CONNECTION, close_header_value());

    builder.body(body.boxed()).unwrap_or_else(|error| {
        tracing::warn!(error = %error, "network proxy: response build error");
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(full_body("Response build error"))
            .expect("static error response must build")
    })
}

fn filtered_end_to_end_headers(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    let connection_scoped = connection_scoped_headers(headers);
    headers
        .iter()
        .filter(|(name, _)| !is_hop_by_hop_header(name, &connection_scoped))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

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

/// Format a host/port pair for TcpStream::connect, including IPv6 brackets.
fn format_target_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Bidirectional tunnel between upgraded connection and target
async fn tunnel(
    upgraded: hyper::upgrade::Upgraded,
    target: TcpStream,
) -> std::result::Result<(), std::io::Error> {
    use futures_lite::io::split;

    // Wrap upgraded connection to implement AsyncRead/AsyncWrite
    let upgraded = UpgradedWrapper(upgraded);

    let (client_read, client_write) = split(upgraded);
    let (target_read, target_write) = split(target);

    let client_to_target = relay_and_close(client_read, target_write);
    let target_to_client = relay_and_close(target_read, client_write);

    // Run both directions concurrently
    let (client_result, target_result) =
        futures_lite::future::zip(client_to_target, target_to_client).await;
    client_result?;
    target_result?;

    Ok(())
}

async fn relay_and_close<R, W>(reader: R, mut writer: W) -> std::io::Result<u64>
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

/// Wrapper for hyper::upgrade::Upgraded to implement futures_lite AsyncRead/AsyncWrite
struct UpgradedWrapper(hyper::upgrade::Upgraded);

impl AsyncRead for UpgradedWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        // Create a ReadBufCursor from our buffer
        let mut read_buf = hyper::rt::ReadBuf::new(buf);

        match hyper::rt::Read::poll_read(Pin::new(&mut self.0), cx, read_buf.unfilled()) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UpgradedWrapper {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        hyper::rt::Write::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        hyper::rt::Write::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        hyper::rt::Write::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

/// Create an empty body
fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Create a body from a string
fn full_body(s: &'static str) -> BoxBody<Bytes, hyper::Error> {
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
    use std::net::Shutdown;
    use std::time::Duration;

    #[test]
    fn test_format_target_addr() {
        assert_eq!(format_target_addr("example.com", 443), "example.com:443");
        assert_eq!(format_target_addr("127.0.0.1", 8080), "127.0.0.1:8080");
        assert_eq!(format_target_addr("::1", 443), "[::1]:443");
        assert_eq!(format_target_addr("2001:db8::1", 80), "[2001:db8::1]:80");
    }

    #[test]
    fn test_filtered_end_to_end_headers_removes_hop_by_hop_headers() {
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

        let filtered = filtered_end_to_end_headers(&headers);

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
    async fn connect_tunnel_propagates_client_half_close() {
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

        let proxy = NetworkProxy::new(AllowAll, executor_core::tokio::TokioGlobal)
            .await
            .expect("proxy starts");
        let mut client = TcpStream::connect(proxy.addr())
            .await
            .expect("client connects to proxy");
        let connect_request =
            format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n");
        client
            .write_all(connect_request.as_bytes())
            .await
            .expect("client writes CONNECT request");

        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            client
                .read_exact(&mut byte)
                .await
                .expect("proxy writes CONNECT response");
            response.push(byte[0]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));

        client
            .write_all(b"ping")
            .await
            .expect("client writes tunneled request");
        client
            .shutdown(Shutdown::Write)
            .expect("client half-closes write side");

        let mut tunneled_response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            client.read_to_end(&mut tunneled_response),
        )
        .await
        .expect("proxy must propagate client EOF to target")
        .expect("client reads tunneled response");
        assert_eq!(tunneled_response, b"pong");

        target.await.expect("target task completes");
    }
}
