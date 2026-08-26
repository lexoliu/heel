//! The sandbox object exposed to JavaScript.

use std::sync::Arc;

use heel::{AllowAll, AllowList, Command as RustCommand, DenyAll, Sandbox as RustSandbox};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use crate::command::{Command, ProcessOutputJs};
use crate::config::SandboxConfigJs;
use crate::error::IntoNapiResult;
use crate::policy::PolicySelection;

/// A sandbox whose network policy was chosen at runtime.
pub(crate) enum SandboxInner {
    DenyAll(RustSandbox<DenyAll>),
    AllowAll(RustSandbox<AllowAll>),
    AllowList(RustSandbox<AllowList>),
}

/// Run the same expression against whichever policy the sandbox was built with.
macro_rules! dispatch {
    ($self:expr, $sandbox:ident => $body:expr) => {
        match $self {
            SandboxInner::DenyAll($sandbox) => $body,
            SandboxInner::AllowAll($sandbox) => $body,
            SandboxInner::AllowList($sandbox) => $body,
        }
    };
}

impl SandboxInner {
    pub(crate) fn command(&self, program: String) -> RustCommand<'_> {
        dispatch!(self, sandbox => sandbox.command(program))
    }

    fn working_dir(&self) -> String {
        dispatch!(self, sandbox => sandbox.working_dir().to_string_lossy().into_owned())
    }

    fn proxy_url(&self) -> Option<String> {
        dispatch!(self, sandbox => sandbox.proxy_url())
    }

    fn keep_working_dir(&mut self) {
        dispatch!(self, sandbox => {
            sandbox.keep_working_dir();
        });
    }

    async fn run_python(&self, script: &str) -> heel::Result<std::process::Output> {
        dispatch!(self, sandbox => sandbox.run_python(script).await)
    }
}

/// A sandbox for running untrusted code with restricted permissions.
///
/// When disposed, the sandbox stops its proxy, kills the processes it spawned,
/// and removes a generated working directory.
#[napi]
pub struct Sandbox {
    inner: Arc<Mutex<Option<SandboxInner>>>,
    working_dir: String,
    proxy_url: Option<String>,
}

#[napi]
impl Sandbox {
    /// Create a sandbox.
    #[napi(factory)]
    pub async fn create(config: Option<SandboxConfigJs>) -> Result<Sandbox> {
        let mut config = config.unwrap_or_else(crate::config::preset_strict);
        let policy = PolicySelection::from_config(config.network.take())?;
        let builder = heel::SandboxConfig::builder();

        // The policy type is resolved here so that a deny-all sandbox gets the
        // kernel-level denial its type selects, rather than a proxy that says no.
        let inner = match policy {
            PolicySelection::DenyAll => SandboxInner::DenyAll(
                RustSandbox::with_config_and_executor(
                    config.apply(builder)?,
                    executor_core::tokio::TokioGlobal,
                )
                .await
                .into_napi()?,
            ),
            PolicySelection::AllowAll => SandboxInner::AllowAll(
                RustSandbox::with_config_and_executor(
                    config.apply(builder.network(AllowAll))?,
                    executor_core::tokio::TokioGlobal,
                )
                .await
                .into_napi()?,
            ),
            PolicySelection::AllowList(domains) => SandboxInner::AllowList(
                RustSandbox::with_config_and_executor(
                    config.apply(builder.network(AllowList::new(domains)))?,
                    executor_core::tokio::TokioGlobal,
                )
                .await
                .into_napi()?,
            ),
        };

        Ok(Self {
            working_dir: inner.working_dir(),
            proxy_url: inner.proxy_url(),
            inner: Arc::new(Mutex::new(Some(inner))),
        })
    }

    /// The working directory path.
    #[napi(getter)]
    pub fn working_dir(&self) -> String {
        self.working_dir.clone()
    }

    /// The proxy URL, or `null` when network access is denied.
    #[napi(getter)]
    pub fn proxy_url(&self) -> Option<String> {
        self.proxy_url.clone()
    }

    /// Build a command to run in the sandbox.
    #[napi]
    pub fn command(&self, program: String) -> Command {
        Command::new(self.inner.clone(), program)
    }

    /// Run a Python script in the sandbox.
    #[napi]
    pub async fn run_python(&self, script: String) -> Result<ProcessOutputJs> {
        let guard = self.inner.lock().await;
        let sandbox = guard.as_ref().ok_or_else(disposed)?;
        let output = sandbox.run_python(&script).await.into_napi()?;
        Ok(ProcessOutputJs::from(output))
    }

    /// Keep the working directory after the sandbox is disposed.
    #[napi]
    pub async fn keep_working_dir(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        guard.as_mut().ok_or_else(disposed)?.keep_working_dir();
        Ok(())
    }

    /// Dispose the sandbox, releasing everything it holds.
    #[napi]
    pub async fn dispose(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        *guard = None;
        Ok(())
    }
}

/// The error reported for any use after disposal.
fn disposed() -> Error {
    Error::from_reason("the sandbox has already been disposed")
}

/// Create a sandbox.
///
/// @example
/// ```typescript
/// import { createSandbox } from 'heel-sandbox';
///
/// const sandbox = await createSandbox();
/// const output = await sandbox.command('/bin/echo').arg('hello').output();
/// console.log(output.stdout.toString()); // "hello\n"
/// ```
#[napi]
pub async fn create_sandbox(config: Option<SandboxConfigJs>) -> Result<Sandbox> {
    Sandbox::create(config).await
}
