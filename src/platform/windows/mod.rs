//! Windows backend, built on AppContainer isolation and job objects.
//!
//! Each sandbox owns one AppContainer profile. The container's token is
//! default-deny against the filesystem, so the configured paths are opened to it
//! by ACL and nothing else is reachable; a job object carries the resource
//! limits and kills the process tree.
//!
//! `std::process::Command` cannot launch into a container: that needs process
//! and thread attributes it does not expose. The launch therefore goes through
//! `rappct`, which returns pipe handles rather than `std::process` streams,
//! which is why [`crate::platform::child::Child`] is generic over its handle.

mod child;
mod container;

use std::process::Output;

use rappct::launch::{
    JobLimits, LaunchOptions, StdioConfig, launch_in_container_with_io, merge_parent_env,
};

pub(crate) use child::AppContainerChild;
use container::Container;

use crate::error::{Error, Result};
use crate::platform::{Backend, Child, SpawnRequest};

/// Windows sandbox backend.
#[derive(Debug)]
pub struct WindowsBackend {
    container: Container,
}

impl WindowsBackend {
    /// Create the AppContainer this sandbox's processes will run in.
    ///
    /// # Errors
    ///
    /// Returns an error if the AppContainer profile cannot be created.
    pub fn new() -> Result<Self> {
        Ok(Self {
            container: Container::create()?,
        })
    }

    /// Prepare everything one launch needs.
    ///
    /// Returns the options, the capabilities and the loopback exemption, which
    /// must outlive the process it is granted for.
    fn prepare(&self, request: &SpawnRequest<'_>) -> Result<Prepared> {
        self.container.grant_configured_paths(request.config)?;

        // The container has to read the program to run it. Anything under the
        // system directories is already open to every package; a program
        // elsewhere is not, so it is granted explicitly.
        let program = which::which(request.program)
            .map_err(|source| Error::path(request.program, std::io::Error::other(source)))?;
        self.container.grant_program(&program)?;

        // A proxy port means a filtering policy, which only works if the
        // container may reach the proxy on loopback.
        let loopback = match request.proxy_port {
            Some(_) => Some(self.container.exempt_loopback()?),
            None => None,
        };

        let limits = request.config.limits();
        let options = LaunchOptions {
            exe: program,
            cmdline: Some(command_line(request)),
            cwd: Some(request.working_dir().to_path_buf()),
            // Windows processes need a handful of variables from the parent --
            // `SystemRoot` above all -- or the loader and much of the Win32 API
            // fail before the program's first instruction. The sandbox's own
            // variables win where the two overlap.
            env: Some(merge_parent_env(
                request
                    .envs
                    .iter()
                    .map(|(key, value)| (key.into(), value.into()))
                    .collect(),
            )),
            stdio: stdio(request.stdout),
            // The launcher configures the three streams together, so the
            // request's stdout decides for all of them; every caller in this
            // crate asks for the same thing on all three anyway.
            suspended: false,
            join_job: Some(JobLimits {
                memory_bytes: limits
                    .max_memory_bytes()
                    .and_then(|v| usize::try_from(v).ok()),
                cpu_rate_percent: None,
                // The sandbox owns the tree: when the job closes, it goes.
                kill_on_job_close: true,
            }),
            startup_timeout: None,
        };

        Ok(Prepared {
            options,
            capabilities: self.container.capabilities(request.proxy_port.is_some())?,
            loopback,
        })
    }

    /// Launch one process into the container.
    fn launch(&self, request: SpawnRequest<'_>) -> Result<Child> {
        let prepared = self.prepare(&request)?;

        let launched = launch_in_container_with_io(&prepared.capabilities, &prepared.options)
            .map_err(|source| {
                Error::InitFailed(format!(
                    "cannot launch {} in the AppContainer: {source}",
                    request.program
                ))
            })?;

        let pid = launched.pid;
        let child = AppContainerChild::new(launched, prepared.loopback)?;
        tracing::debug!(program = %request.program, pid, "sandbox: spawned");

        Ok(Child::new(child))
    }
}

/// Everything one launch needs, built before the process starts.
struct Prepared {
    options: LaunchOptions,
    capabilities: rappct::capability::SecurityCapabilities,
    loopback: Option<rappct::net::LoopbackExemptionGuard>,
}

/// Build the command line the process sees.
///
/// Windows passes one string and lets the process parse it, so each argument is
/// quoted the way the C runtime expects to read it back.
fn command_line(request: &SpawnRequest<'_>) -> String {
    std::iter::once(request.program)
        .chain(request.args.iter().map(String::as_str))
        .map(quote)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quote one argument for the Windows command-line convention.
fn quote(argument: &str) -> String {
    if !argument.is_empty() && !argument.contains([' ', '\t', '"', '\\']) {
        return argument.to_string();
    }

    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for character in argument.chars() {
        match character {
            '\\' => {
                backslashes += 1;
                quoted.push('\\');
            }
            '"' => {
                // Backslashes before a quote are doubled, then the quote is
                // escaped; anywhere else they are literal.
                quoted.extend(std::iter::repeat_n('\\', backslashes + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                backslashes = 0;
                quoted.push(character);
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes));
    quoted.push('"');
    quoted
}

/// Map a standard-stream configuration onto the launcher's.
fn stdio(configured: crate::command::StdioConfig) -> StdioConfig {
    match configured {
        crate::command::StdioConfig::Inherit => StdioConfig::Inherit,
        crate::command::StdioConfig::Piped => StdioConfig::Pipe,
        crate::command::StdioConfig::Null => StdioConfig::Null,
    }
}

impl Backend for WindowsBackend {
    async fn execute(&self, request: SpawnRequest<'_>) -> Result<Output> {
        tracing::debug!(program = %request.program, args = ?request.args, "sandbox: executing");

        let child = self.launch(request)?;
        child.wait_with_output().await
    }

    async fn spawn(&self, request: SpawnRequest<'_>) -> Result<Child> {
        tracing::debug!(program = %request.program, args = ?request.args, "sandbox: spawning");

        self.launch(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_arguments_are_not_quoted() {
        assert_eq!(quote("simple"), "simple");
    }

    #[test]
    fn arguments_with_spaces_are_quoted() {
        assert_eq!(quote("two words"), "\"two words\"");
    }

    #[test]
    fn embedded_quotes_are_escaped() {
        assert_eq!(quote("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn trailing_backslashes_are_doubled_before_the_closing_quote() {
        assert_eq!(quote("dir\\"), "\"dir\\\\\"");
    }

    #[test]
    fn an_empty_argument_survives_as_an_empty_string() {
        assert_eq!(quote(""), "\"\"");
    }
}
