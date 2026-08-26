//! Shared accept loop for the sandbox's local servers.
//!
//! Both the network proxy and the IPC server accept connections until the
//! sandbox shuts them down. Shutdown is signalled by closing a channel rather
//! than by polling a flag, so an idle server costs zero wakeups.

use std::io;

use async_channel::{Receiver, Sender, bounded};
use futures_lite::{Stream, StreamExt};

/// Signals a running accept loop to stop.
///
/// Dropping the signal stops the loop, so a server that owns its signal is
/// stopped by dropping the server.
#[derive(Debug)]
pub(crate) struct ShutdownSignal {
    sender: Sender<()>,
}

impl ShutdownSignal {
    /// Create a shutdown signal and the receiver to hand to [`accept_loop`].
    pub(crate) fn new() -> (Self, Receiver<()>) {
        let (sender, receiver) = bounded(1);
        (Self { sender }, receiver)
    }

    /// Stop the accept loop.
    pub(crate) fn stop(&self) {
        self.sender.close();
    }
}

impl Drop for ShutdownSignal {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Accept connections until the listener closes or shutdown is signalled.
///
/// `on_connection` is called for each accepted connection and is expected to
/// hand the work off to a task rather than block the loop.
pub(crate) async fn accept_loop<S, C, F>(
    mut incoming: S,
    shutdown: Receiver<()>,
    server: &'static str,
    mut on_connection: F,
) where
    S: Stream<Item = io::Result<C>> + Unpin,
    F: FnMut(C),
{
    loop {
        // `or` polls the accept future first, so pending connections win over a
        // simultaneous shutdown and no connection is dropped on the floor.
        let accepted = futures_lite::future::or(async { Some(incoming.next().await) }, async {
            // Resolves when `stop()` is called or the signal is dropped.
            let _ = shutdown.recv().await;
            None
        })
        .await;

        match accepted {
            Some(Some(Ok(connection))) => on_connection(connection),
            Some(Some(Err(error))) => {
                tracing::warn!(server, %error, "failed to accept connection");
            }
            Some(None) => {
                tracing::debug!(server, "listener closed");
                break;
            }
            None => {
                tracing::debug!(server, "shutdown signalled");
                break;
            }
        }
    }
}
