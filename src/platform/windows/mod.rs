//! Windows backend, built on AppContainer isolation and job objects.
//!
//! Each sandbox owns one AppContainer profile. The container's token is
//! default-deny against the filesystem, so the configured paths are opened to it
//! by ACL and nothing else is reachable; a job object carries the resource
//! limits and kills the process tree.
//!
//! `std::process::Command` cannot launch into a container: the container
//! assignment, the job and the std handles all live in process attributes it
//! does not expose. The launch is therefore made directly, which returns pipe
//! handles rather than `std::process` streams — and that is why
//! [`crate::platform::child::Child`] is generic over its handle.

mod acl;
mod capability;
mod child;
mod container;
mod launch;
#[cfg(test)]
mod launch_tests;
mod loopback;
mod priority;
mod profile;
mod sid;

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::Output;

pub(crate) use child::AppContainerChild;
use container::Container;
use loopback::LoopbackExemption;
use sid::Sid;

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::platform::{Backend, Child, SpawnRequest, env_name_eq};

/// A launch-prep failure that names the call which produced it.
///
/// Backend internals return this so the boundaries can wrap it once — in
/// `Error::InitFailed` — and `with_causes` prints the call and the OS error
/// the call returned, exactly once each.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Win32Failure {
    /// A Win32 call returned an error; `call` names it.
    #[error("{call} failed")]
    Win32 {
        /// The call that failed.
        call: &'static str,
        /// The error it returned.
        #[source]
        source: windows::core::Error,
    },
    /// A Rust-side call failed; `call` names it.
    #[error("{call} failed")]
    Io {
        /// The call that failed.
        call: &'static str,
        /// The error it returned.
        #[source]
        source: io::Error,
    },
    /// A value the launch needed was malformed before any call ran.
    #[error("{0}")]
    Invalid(String),
    /// An error that already carries heel context.
    #[error(transparent)]
    Internal(#[from] Error),
}

impl Win32Failure {
    /// Build a failure for the Win32 call `call` — for use with `map_err`.
    fn call(call: &'static str) -> impl FnOnce(windows::core::Error) -> Self {
        move |source| Self::Win32 { call, source }
    }

    /// Build a failure for the Rust-side call `call` — for use with `map_err`.
    fn io(call: &'static str) -> impl FnOnce(io::Error) -> Self {
        move |source| Self::Io { call, source }
    }
}

/// Variables a launched process inherits when the request does not replace
/// the parent's environment.
///
/// A custom environment replaces the parent's entirely, and a process without
/// `SystemRoot` or `ComSpec` fails before its first instruction, so these are
/// filled in when nothing supplied them. Windows compares names
/// case-insensitively, so the check does too — a `PATH` the caller spelled
/// `Path` must not be duplicated.
const INHERITED_VARIABLES: &[&str] = &["SystemRoot", "windir", "ComSpec", "PATHEXT", "PATH"];

/// Machine facts a Windows process expects to find in its environment.
///
/// The inherited variables already fill in `SystemRoot`, `windir`, `ComSpec`
/// and `PATHEXT`. These are the rest of what the loader
/// and the C runtime consult, and they describe the machine rather than the
/// user, so passing them through leaks nothing: the user's own variables stay
/// out.
const MACHINE_FACTS: &[&str] = &[
    "SystemDrive",
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "NUMBER_OF_PROCESSORS",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramW6432",
];

/// User directories retained from the parent environment.
///
/// They name the user, which a sandbox would rather not disclose, but nothing
/// is disclosed that was not already: the container's temporary directory sits
/// under the user's profile, so its path carries the user's name regardless.
/// The remaining entries are passed for what Windows and the C runtime consult.
/// `LOCALAPPDATA` is set separately from the profile folder.
const USER_DIRECTORIES: &[&str] = &["USERPROFILE", "APPDATA", "ALLUSERSPROFILE"];

/// Windows sandbox backend.
#[derive(Debug)]
pub struct WindowsBackend {
    container: Container,
}

impl WindowsBackend {
    /// Create the AppContainer this sandbox's processes will run in, and open
    /// the configured paths to it.
    ///
    /// The paths are granted here rather than at the first launch because
    /// Windows grants by inheritance: setting the entries propagates them to
    /// what the tree already holds, and they must all be in place before the
    /// process starts creating its own files so those inherit them too.
    ///
    /// # Errors
    ///
    /// Returns an error if the AppContainer profile cannot be created, or if a
    /// configured path cannot be opened to it.
    pub fn new(config: &SandboxConfigData) -> Result<Self> {
        let container = Container::create()?;
        container.grant_configured_paths(config)?;
        Ok(Self { container })
    }

    /// Open the sandbox's IPC endpoint to the container.
    ///
    /// The endpoint is a named pipe — a kernel object whose default access
    /// control list names nothing an AppContainer token carries — so the pipe
    /// bound for `socket` is granted once the server has bound it.
    pub(crate) fn grant_ipc_endpoint(&self, socket: &Path) -> Result<()> {
        self.container.grant_ipc_endpoint(socket)
    }

    /// Prepare everything one launch needs.
    ///
    /// Returns the program, the capability and the loopback exemption, the
    /// last of which must outlive the process it is granted for.
    fn prepare(&self, request: &SpawnRequest<'_>) -> Result<Prepared> {
        // The container has to read the program to run it. Anything under the
        // system directories is already open to every package; a program
        // elsewhere is not, so it is granted explicitly.
        let path = request
            .envs
            .iter()
            .rev()
            .find(|(name, _)| env_name_eq(name, "PATH"))
            .map(|(_, value)| value);
        // A program that does not resolve names the search it failed: the
        // sandbox's PATH is computed from the request and the passthrough
        // list, so the caller cannot otherwise tell which one it was.
        let program =
            which::which_in(request.program, path, request.working_dir()).map_err(|source| {
                let pathext = std::env::var_os("PATHEXT");
                Error::path(
                    request.program,
                    std::io::Error::other(format!(
                        "{source} (PATH searched: {}; PATHEXT: {})",
                        path.map_or("unset", String::as_str),
                        pathext
                            .as_deref()
                            .map_or("unset".into(), |ext| ext.to_string_lossy()),
                    )),
                )
            })?;
        let capability = self.container.capabilities(request.proxy_port.is_some())?;
        self.container
            .grant_program(&program, capability.as_ref())?;

        // A proxy port means a filtering policy, which only works if the
        // container may reach the proxy on loopback.
        let loopback = match request.proxy_port {
            Some(_) => Some(self.container.exempt_loopback()?),
            None => None,
        };

        Ok(Prepared {
            program,
            capability,
            loopback,
        })
    }

    /// Launch one process into the container.
    fn launch(&self, request: SpawnRequest<'_>) -> Result<Child> {
        let prepared = self.prepare(&request)?;

        let limits = request.config.limits();
        // The launcher configures the three streams together, so the
        // request's stdout decides for all of them; every caller in this
        // crate asks for the same thing on all three anyway.
        let options = launch::Launch {
            package: self.container.sid(),
            capability: prepared.capability.as_ref(),
            exe: prepared.program,
            cmdline: command_line(&request),
            cwd: request.working_dir().to_path_buf(),
            env: environment(
                &request,
                self.container.local_app_data(),
                self.container.profile_folder(),
            ),
            stdio: stdio(request.stdout),
            memory_bytes: limits
                .max_memory_bytes()
                .and_then(|v| usize::try_from(v).ok()),
            priority: request.config.priority(),
        };

        let launched = launch::launch(&options).map_err(|source| {
            Error::InitFailed(format!(
                "cannot launch {} in the AppContainer from {}: {}; environment was {}",
                request.program,
                request.working_dir().display(),
                with_causes(&source),
                describe(&options.env),
            ))
        })?;

        let pid = launched.pid;
        let child = AppContainerChild::new(launched, prepared.loopback);
        tracing::debug!(program = %request.program, pid, "sandbox: spawned");

        Ok(Child::new(child))
    }
}

/// The environment the sandboxed process starts with.
///
/// Windows processes need a handful of variables from the parent -- `SystemRoot`
/// above all -- or the loader and much of the Win32 API fail before the
/// program's first instruction. The sandbox's own variables win where the two
/// overlap, because an inherited variable is added only when nothing supplied
/// it.
///
/// The result has to be sorted case-insensitively by name: `CreateProcessW`
/// refuses an unsorted block with `ERROR_ENVVAR_NOT_FOUND`, which names no
/// variable and reads like something else entirely. Inherited variables are
/// appended to whatever the request supplied, so sorting has to happen after
/// them rather than at the point the variables are collected.
fn environment(
    request: &SpawnRequest<'_>,
    local_app_data: &Path,
    profile_folder: &Path,
) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = request
        .envs
        .iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();

    // Variables the caller named for pass-through join whatever the request
    // already carries. What the request supplies wins where the two overlap.
    for name in request.config.env_passthrough() {
        if let Some(value) = std::env::var_os(name)
            && !supplied(&env, name)
        {
            env.push((name.into(), value));
        }
    }

    for name in MACHINE_FACTS.iter().chain(USER_DIRECTORIES) {
        if let Some(value) = std::env::var_os(name)
            && !supplied(&env, name)
        {
            env.push(((*name).into(), value));
        }
    }

    for name in INHERITED_VARIABLES {
        if let Some(value) = std::env::var_os(name)
            && !supplied(&env, name)
        {
            env.push(((*name).into(), value));
        }
    }

    // Windows rewrites a child's LOCALAPPDATA to
    // `<LOCALAPPDATA>\Packages\<profile>\AC` and derives TEMP/TMP beneath it.
    // GetAppContainerFolderPath reports the existing profile folder; passing
    // its validated base makes the rewritten value name that folder. The
    // explicit TEMP/TMP values match what Windows derives, and TMPDIR follows
    // TEMP for programs that consult it.
    env.retain(|(name, _)| {
        !["LOCALAPPDATA", "TEMP", "TMP", "TMPDIR"]
            .iter()
            .any(|reserved| env_name_eq(name, reserved))
    });
    let temp = profile_folder.join("Temp");
    env.push(("LOCALAPPDATA".into(), local_app_data.as_os_str().to_owned()));
    env.push(("TEMP".into(), temp.as_os_str().to_owned()));
    env.push(("TMP".into(), temp.as_os_str().to_owned()));
    env.push(("TMPDIR".into(), temp.as_os_str().to_owned()));

    env.sort_by_cached_key(|(name, _)| name.to_string_lossy().to_lowercase());
    env
}

/// Whether `env` already supplies `name`.
///
/// Windows compares variable names case-insensitively, so the check does too:
/// a `PATH` the request spelled `Path` must not sit beside the variable being
/// filled in behind it.
fn supplied(env: &[(OsString, OsString)], name: &str) -> bool {
    env.iter().any(|(existing, _)| env_name_eq(existing, name))
}

/// Summarize a launch's environment for a failure message.
///
/// `CreateProcessW` reports a malformed environment block as
/// `ERROR_ENVVAR_NOT_FOUND`, which names nothing and points at no entry, so the
/// entries themselves have to be in the message to be diagnosable at all. Only
/// names and value lengths are shown: values carry proxy URLs and paths, and a
/// failure message is not the place to print them.
fn describe(env: &[(OsString, OsString)]) -> String {
    let entries = env
        .iter()
        .map(|(name, value)| {
            let name = name.to_string_lossy();
            let flag = if name.is_empty() {
                " <EMPTY NAME>"
            } else if name.contains('=') {
                " <NAME CONTAINS =>"
            } else {
                ""
            };
            format!("{name}[{}]{flag}", value.len())
        })
        .collect::<Vec<_>>()
        .join(", ");

    format!("{} entries: {entries}", env.len())
}

/// Render an error together with everything that caused it.
///
/// The launcher's `Display` names the stage it failed at and keeps the reason
/// the operating system gave as a source, so printing it alone says only that
/// something went wrong and not what.
pub(crate) fn with_causes(error: &dyn std::error::Error) -> String {
    std::iter::successors(Some(error), |error| error.source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

/// Encode `value` as a NUL-terminated UTF-16 string for `*_W` parameters.
fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Everything one launch needs, built before the process starts.
struct Prepared {
    /// The resolved path to the program to run.
    program: std::path::PathBuf,
    /// `internetClient`, when the process may reach the proxy.
    capability: Option<Sid>,
    /// The loopback exemption, held for the life of the process.
    loopback: Option<LoopbackExemption>,
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
fn stdio(configured: crate::command::StdioConfig) -> launch::Stdio {
    match configured {
        crate::command::StdioConfig::Inherit => launch::Stdio::Inherit,
        crate::command::StdioConfig::Piped => launch::Stdio::Pipe,
        crate::command::StdioConfig::Null => launch::Stdio::Null,
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

    // The public types must stay Send+Sync: callers hold a `Sandbox`/`Child`
    // inside async state (per-chat actors, daemons) whose futures spawn onto
    // multi-threaded executors. Everything the backend owns is an ordinary
    // `Send`/`Sync` value — owned SIDs, `OwnedHandle`s, `File`s — and this
    // keeps a stray raw pointer from regressing it silently.
    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<crate::Sandbox>();
        assert_send_sync::<crate::Child>();
    };

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
