use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use crate::command::{Command, ProcessOutputJs};
use crate::config::SandboxConfigJs;
use crate::error::IntoNapiResult;
use crate::network::NetworkPolicyWrapper;

/// Internal sandbox wrapper that owns the Rust sandbox
pub(crate) struct SandboxInner {
    pub sandbox: heel::Sandbox<NetworkPolicyWrapper>,
}

/// A sandbox for running untrusted code with restricted permissions
///
/// All network traffic from sandboxed processes is routed through a local proxy
/// that applies the configured network policy for filtering.
///
/// When disposed, the sandbox will:
/// - Stop the network proxy
/// - Stop the IPC server (if enabled)
/// - Kill all child processes that were spawned within it
/// - Delete the working directory if it was auto-created (unless `keepWorkingDir()` was called)
#[napi]
pub struct Sandbox {
    inner: Arc<Mutex<Option<SandboxInner>>>,
    working_dir: String,
    proxy_url: String,
}

#[napi]
impl Sandbox {
    /// Create a new sandbox with optional configuration
    #[napi(factory)]
    pub async fn create(config: Option<SandboxConfigJs>) -> Result<Sandbox> {
        // Build the Rust config - do this before any await points
        let rust_config = match config {
            Some(cfg) => cfg.into_rust_config()?,
            None => heel::SandboxConfig::builder()
                .network(NetworkPolicyWrapper::deny_all())
                .build()
                .into_napi()?,
        };

        // Create the sandbox with tokio executor
        let sandbox =
            heel::Sandbox::with_config_and_executor(rust_config, executor_core::tokio::TokioGlobal)
                .await
                .into_napi()?;

        let working_dir = sandbox.working_dir().to_string_lossy().to_string();
        let proxy_url = sandbox.proxy_url();

        Ok(Self {
            inner: Arc::new(Mutex::new(Some(SandboxInner { sandbox }))),
            working_dir,
            proxy_url,
        })
    }

    /// Get the working directory path
    #[napi(getter)]
    pub fn working_dir(&self) -> String {
        self.working_dir.clone()
    }

    /// Get the proxy URL for environment variables
    #[napi(getter)]
    pub fn proxy_url(&self) -> String {
        self.proxy_url.clone()
    }

    /// Create a command builder for running a program in the sandbox
    #[napi]
    pub fn command(&self, program: String) -> Command {
        Command::new(self.inner.clone(), program)
    }

    /// Run a Python script in the sandbox
    #[napi]
    pub async fn run_python(&self, script: String) -> Result<ProcessOutputJs> {
        let guard = self.inner.lock().await;
        let sandbox_inner = guard
            .as_ref()
            .ok_or_else(|| Error::from_reason("Sandbox already disposed"))?;

        let output = sandbox_inner
            .sandbox
            .run_python(&script)
            .await
            .into_napi()?;

        Ok(ProcessOutputJs::from(output))
    }

    /// Keep the working directory after the sandbox is disposed
    #[napi]
    pub async fn keep_working_dir(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Some(ref mut inner) = *guard {
            inner.sandbox.keep_working_dir();
        }
        Ok(())
    }

    /// Dispose the sandbox (called automatically, but can be called manually)
    ///
    /// This will:
    /// - Stop the network proxy
    /// - Kill all child processes
    /// - Delete the working directory if it was auto-created (unless keepWorkingDir was called)
    #[napi]
    pub async fn dispose(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        *guard = None; // Drop triggers cleanup
        Ok(())
    }
}

/// Create a new sandbox with optional configuration
///
/// This is the main entry point for creating sandboxes.
///
/// @example
/// ```typescript
/// import { createSandbox } from 'heel-sandbox';
///
/// const sandbox = await createSandbox();
/// const output = await sandbox.command('echo').arg('hello').output();
/// console.log(output.stdout.toString()); // "hello\n"
/// ```
#[napi]
pub async fn create_sandbox(config: Option<SandboxConfigJs>) -> Result<Sandbox> {
    Sandbox::create(config).await
}
