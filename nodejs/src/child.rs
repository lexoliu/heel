use std::io::{Read, Write};
use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use crate::command::{ExitStatusJs, ProcessOutputJs};
use crate::error::IntoNapiResult;

/// A spawned child process in the sandbox
#[napi]
pub struct ChildProcessJs {
    inner: Arc<Mutex<heel::Child>>,
    pid: u32,
}

impl ChildProcessJs {
    pub(crate) fn new(child: heel::Child) -> Self {
        let pid = child.id();
        Self {
            inner: Arc::new(Mutex::new(child)),
            pid,
        }
    }
}

#[napi]
impl ChildProcessJs {
    /// Get the process ID
    #[napi(getter)]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Wait for the process to exit
    #[napi]
    pub async fn wait(&self) -> Result<ExitStatusJs> {
        let mut guard = self.inner.lock().await;
        let status = guard.wait().await.into_napi()?;
        Ok(ExitStatusJs {
            success: status.success(),
            code: status.code(),
        })
    }

    /// Wait for the process to exit and collect all output
    #[napi]
    pub async fn wait_with_output(&self) -> Result<ProcessOutputJs> {
        // We need to take ownership of the child for wait_with_output
        // This is a limitation - after calling this, the child is consumed
        let mut guard = self.inner.lock().await;

        // Read remaining stdout/stderr before waiting
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        if let Some(stdout) = guard.take_stdout() {
            let mut stdout = stdout;
            let _ = stdout.read_to_end(&mut stdout_buf);
        }

        if let Some(stderr) = guard.take_stderr() {
            let mut stderr = stderr;
            let _ = stderr.read_to_end(&mut stderr_buf);
        }

        let status = guard.wait().await.into_napi()?;

        Ok(ProcessOutputJs {
            status: ExitStatusJs {
                success: status.success(),
                code: status.code(),
            },
            stdout: stdout_buf.into(),
            stderr: stderr_buf.into(),
        })
    }

    /// Kill the process
    #[napi]
    pub async fn kill(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        guard.kill().into_napi()
    }

    /// Check if the process has exited without blocking
    #[napi]
    pub async fn try_wait(&self) -> Result<Option<ExitStatusJs>> {
        let mut guard = self.inner.lock().await;
        let status = guard.try_wait().into_napi()?;
        Ok(status.map(|s| ExitStatusJs {
            success: s.success(),
            code: s.code(),
        }))
    }

    /// Write data to the process stdin
    #[napi]
    pub async fn write_stdin(&self, data: Buffer) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Some(stdin) = guard.stdin() {
            stdin
                .write_all(&data)
                .map_err(|e| Error::from_reason(format!("Failed to write to stdin: {}", e)))?;
            stdin
                .flush()
                .map_err(|e| Error::from_reason(format!("Failed to flush stdin: {}", e)))?;
            Ok(())
        } else {
            Err(Error::from_reason("stdin not available"))
        }
    }

    /// Read available data from stdout (non-blocking)
    #[napi]
    pub async fn read_stdout(&self, max_bytes: u32) -> Result<Buffer> {
        let mut guard = self.inner.lock().await;
        if let Some(stdout) = guard.stdout() {
            let mut buf = vec![0u8; max_bytes as usize];
            match stdout.read(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    Ok(buf.into())
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Vec::new().into()),
                Err(e) => Err(Error::from_reason(format!(
                    "Failed to read from stdout: {}",
                    e
                ))),
            }
        } else {
            Err(Error::from_reason("stdout not available"))
        }
    }

    /// Read available data from stderr (non-blocking)
    #[napi]
    pub async fn read_stderr(&self, max_bytes: u32) -> Result<Buffer> {
        let mut guard = self.inner.lock().await;
        if let Some(stderr) = guard.stderr() {
            let mut buf = vec![0u8; max_bytes as usize];
            match stderr.read(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    Ok(buf.into())
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Vec::new().into()),
                Err(e) => Err(Error::from_reason(format!(
                    "Failed to read from stderr: {}",
                    e
                ))),
            }
        } else {
            Err(Error::from_reason("stderr not available"))
        }
    }
}
