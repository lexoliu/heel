use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use crate::child::ChildProcessJs;
use crate::error::IntoNapiResult;
use crate::sandbox::SandboxInner;

/// Standard I/O configuration
#[napi(string_enum)]
pub enum StdioConfigJs {
    /// Inherit from parent process
    Inherit,
    /// Create a new pipe
    Piped,
    /// Redirect to null
    Null,
}

impl From<StdioConfigJs> for heel::StdioConfig {
    fn from(config: StdioConfigJs) -> Self {
        match config {
            StdioConfigJs::Inherit => heel::StdioConfig::Inherit,
            StdioConfigJs::Piped => heel::StdioConfig::Piped,
            StdioConfigJs::Null => heel::StdioConfig::Null,
        }
    }
}

/// Process exit status
#[napi(object)]
#[derive(Clone)]
pub struct ExitStatusJs {
    pub success: bool,
    pub code: Option<i32>,
}

/// Process output with stdout and stderr
#[napi(object)]
pub struct ProcessOutputJs {
    pub status: ExitStatusJs,
    #[napi(ts_type = "Buffer")]
    pub stdout: Buffer,
    #[napi(ts_type = "Buffer")]
    pub stderr: Buffer,
}

impl From<std::process::Output> for ProcessOutputJs {
    fn from(output: std::process::Output) -> Self {
        Self {
            status: ExitStatusJs {
                success: output.status.success(),
                code: output.status.code(),
            },
            stdout: output.stdout.into(),
            stderr: output.stderr.into(),
        }
    }
}

/// Command builder for executing programs in the sandbox
#[napi]
pub struct Command {
    sandbox: Arc<Mutex<Option<SandboxInner>>>,
    program: String,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    cwd: Option<String>,
    stdin: StdioConfigJs,
    stdout: StdioConfigJs,
    stderr: StdioConfigJs,
}

impl Command {
    pub(crate) fn new(sandbox: Arc<Mutex<Option<SandboxInner>>>, program: String) -> Self {
        Self {
            sandbox,
            program,
            args: Vec::new(),
            envs: Vec::new(),
            cwd: None,
            stdin: StdioConfigJs::Inherit,
            stdout: StdioConfigJs::Inherit,
            stderr: StdioConfigJs::Inherit,
        }
    }
}

#[napi]
impl Command {
    /// Add a single argument
    #[napi]
    pub fn arg(&mut self, value: String) -> &Self {
        self.args.push(value);
        self
    }

    /// Add multiple arguments
    #[napi]
    pub fn args(&mut self, values: Vec<String>) -> &Self {
        self.args.extend(values);
        self
    }

    /// Set an environment variable
    #[napi]
    pub fn env(&mut self, key: String, value: String) -> &Self {
        self.envs.push((key, value));
        self
    }

    /// Set multiple environment variables
    #[napi]
    pub fn envs(&mut self, vars: Vec<Vec<String>>) -> &Self {
        for pair in vars {
            if pair.len() >= 2 {
                self.envs.push((pair[0].clone(), pair[1].clone()));
            }
        }
        self
    }

    /// Set the working directory
    #[napi]
    pub fn cwd(&mut self, dir: String) -> &Self {
        self.cwd = Some(dir);
        self
    }

    /// Configure stdin
    #[napi]
    pub fn stdin(&mut self, config: StdioConfigJs) -> &Self {
        self.stdin = config;
        self
    }

    /// Configure stdout
    #[napi]
    pub fn stdout(&mut self, config: StdioConfigJs) -> &Self {
        self.stdout = config;
        self
    }

    /// Configure stderr
    #[napi]
    pub fn stderr(&mut self, config: StdioConfigJs) -> &Self {
        self.stderr = config;
        self
    }

    /// Run the command and collect all output
    #[napi]
    pub async fn output(&self) -> Result<ProcessOutputJs> {
        let guard = self.sandbox.lock().await;
        let sandbox = guard
            .as_ref()
            .ok_or_else(|| Error::from_reason("Sandbox already disposed"))?;

        let mut cmd = sandbox.sandbox.command(&self.program);

        // Apply configuration
        cmd = cmd.args(&self.args);
        for (k, v) in &self.envs {
            cmd = cmd.env(k, v);
        }
        if let Some(ref dir) = self.cwd {
            cmd = cmd.current_dir(dir);
        }
        cmd = cmd
            .stdin(self.stdin.into())
            .stdout(heel::StdioConfig::Piped) // Always pipe for output()
            .stderr(heel::StdioConfig::Piped);

        let output = cmd.output().await.into_napi()?;
        Ok(ProcessOutputJs::from(output))
    }

    /// Run the command and return only exit status
    #[napi]
    pub async fn status(&self) -> Result<ExitStatusJs> {
        let guard = self.sandbox.lock().await;
        let sandbox = guard
            .as_ref()
            .ok_or_else(|| Error::from_reason("Sandbox already disposed"))?;

        let mut cmd = sandbox.sandbox.command(&self.program);

        // Apply configuration
        cmd = cmd.args(&self.args);
        for (k, v) in &self.envs {
            cmd = cmd.env(k, v);
        }
        if let Some(ref dir) = self.cwd {
            cmd = cmd.current_dir(dir);
        }
        cmd = cmd
            .stdin(self.stdin.into())
            .stdout(self.stdout.into())
            .stderr(self.stderr.into());

        let status = cmd.status().await.into_napi()?;
        Ok(ExitStatusJs {
            success: status.success(),
            code: status.code(),
        })
    }

    /// Spawn the command as a child process
    #[napi]
    pub async fn spawn(&self) -> Result<ChildProcessJs> {
        let guard = self.sandbox.lock().await;
        let sandbox = guard
            .as_ref()
            .ok_or_else(|| Error::from_reason("Sandbox already disposed"))?;

        let mut cmd = sandbox.sandbox.command(&self.program);

        // Apply configuration
        cmd = cmd.args(&self.args);
        for (k, v) in &self.envs {
            cmd = cmd.env(k, v);
        }
        if let Some(ref dir) = self.cwd {
            cmd = cmd.current_dir(dir);
        }
        cmd = cmd
            .stdin(self.stdin.into())
            .stdout(self.stdout.into())
            .stderr(self.stderr.into());

        let child = cmd.spawn().await.into_napi()?;
        Ok(ChildProcessJs::new(child))
    }
}
