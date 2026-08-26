//! Interactive sessions on a pseudo-terminal.
//!
//! A piped [`Command`](crate::Command) cannot host an interactive shell: line
//! editing, job control and full-screen programs all need a real terminal. This
//! module allocates one, runs the sandboxed program on it, and relays bytes
//! between it and the caller's terminal.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::Duration;

use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use polling::{Event, Events, Poller};
use pty_process::blocking::Pty;

use crate::command::sandbox_environment;
use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::sandbox::ProcessTracker;

/// Everything needed to run one interactive session.
pub struct PtySession<'a> {
    /// Policy-independent sandbox configuration.
    pub config: &'a SandboxConfigData,
    /// Port of the sandbox proxy, when network access is enabled.
    pub proxy_port: Option<u16>,
    /// Proxy URL to publish to the sandboxed process.
    pub proxy_url: Option<String>,
    /// Tracker that kills the session if the sandbox is dropped first.
    pub tracker: &'a ProcessTracker,
    /// Program to run.
    pub program: &'a str,
    /// Arguments for the program.
    pub args: &'a [String],
    /// Extra environment variables.
    pub envs: &'a [(String, String)],
    /// Working directory override.
    pub current_dir: Option<&'a Path>,
}

/// How often the relay loop wakes to notice a resized window or a child exit.
///
/// Both are edge cases the poller cannot report directly, and neither is
/// latency-critical.
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_millis(100);

const STDIN_KEY: usize = 0;
const PTY_KEY: usize = 1;

/// The control character a terminal in canonical mode reads as end-of-input.
///
/// Closing the caller's standard input does not close the pty, so the child
/// would keep waiting for input that can never arrive. Sending EOT tells it
/// what actually happened.
const END_OF_TRANSMISSION: u8 = 0x04;

/// Run a program on a pseudo-terminal inside the sandbox.
///
/// Returns the program's exit status, including the signal that killed it if
/// there was one.
pub fn run_with_pty(session: PtySession<'_>) -> Result<ExitStatus> {
    let (mut pty, pts) = pty_process::blocking::open()
        .map_err(|e| Error::Pty(format!("failed to open PTY: {e}")))?;

    resize_to_terminal(&pty);

    let profile = crate::platform::macos::generate_profile(session.config, session.proxy_port)?;
    let working_dir = session.current_dir.unwrap_or(session.config.working_dir());

    let mut cmd = pty_process::blocking::Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(&profile)
        .arg(session.program)
        .args(session.args)
        .current_dir(working_dir)
        .env_clear();

    for var in session.config.env_passthrough() {
        if let Ok(value) = std::env::var(var) {
            cmd = cmd.env(var, value);
        }
    }

    // An interactive session needs a terminal type; everything else about the
    // environment is built the same way as for a non-interactive command.
    let mut envs = session.envs.to_vec();
    if !envs.iter().any(|(key, _)| key == "TERM") && std::env::var_os("TERM").is_none() {
        envs.push(("TERM".to_string(), "xterm-256color".to_string()));
    }
    for (key, value) in sandbox_environment(session.config, session.proxy_url.as_deref(), &envs) {
        cmd = cmd.env(key, value);
    }

    let mut child = cmd
        .spawn(pts)
        .map_err(|e| Error::Pty(format!("failed to spawn command: {e}")))?;

    // Registered so that dropping the sandbox kills an interactive session too.
    session.tracker.register(child.id());
    let pid = child.id();

    let _raw_mode = RawMode::enable()?;
    let result = relay(&mut pty, &mut child);
    session.tracker.unregister(pid);
    result
}

/// Match the pty's window size to the caller's terminal.
fn resize_to_terminal(pty: &Pty) {
    if let Ok((cols, rows)) = crossterm::terminal::size() {
        let _ = pty.resize(pty_process::Size::new(rows, cols));
    }
}

/// Raw mode on the caller's terminal, restored however the session ends.
///
/// Without the guard, an error path or a panic would leave the user's shell
/// with echo disabled.
struct RawMode {
    enabled: bool,
}

impl RawMode {
    fn enable() -> Result<Self> {
        // SAFETY: `isatty` only inspects a descriptor number and has no
        // preconditions beyond that.
        let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
        if !is_tty {
            return Ok(Self { enabled: false });
        }

        enable_raw_mode().map_err(|e| Error::Pty(format!("failed to enable raw mode: {e}")))?;
        Ok(Self { enabled: true })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if self.enabled {
            let _ = disable_raw_mode();
        }
    }
}

/// A file descriptor's `O_NONBLOCK` flag, restored on drop.
///
/// Standard input is shared with the process that launched the sandbox, so
/// leaving it non-blocking would break the caller's shell after the session
/// ends.
struct NonBlocking {
    fd: i32,
    previous_flags: i32,
}

impl NonBlocking {
    fn set(fd: i32) -> Result<Self> {
        // SAFETY: `fd` is owned by the caller for the lifetime of this value,
        // and reading its flags has no other effect.
        let previous_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if previous_flags == -1 {
            return Err(Error::Pty(format!(
                "failed to read descriptor flags: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: same descriptor, setting the flags just read.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, previous_flags | libc::O_NONBLOCK) } == -1 {
            return Err(Error::Pty(format!(
                "failed to set non-blocking mode: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self { fd, previous_flags })
    }
}

impl Drop for NonBlocking {
    fn drop(&mut self) {
        // SAFETY: restoring the flags this value captured on construction.
        unsafe { libc::fcntl(self.fd, libc::F_SETFL, self.previous_flags) };
    }
}

/// Relay bytes between the caller's terminal and the pty until the child exits.
fn relay(pty: &mut Pty, child: &mut Child) -> Result<ExitStatus> {
    let poller = Poller::new().map_err(|e| Error::Pty(format!("failed to create poller: {e}")))?;
    let mut events = Events::new();

    let stdin = std::io::stdin();
    let stdin_fd = stdin.as_raw_fd();
    let pty_fd = pty.as_raw_fd();

    let _pty_flags = NonBlocking::set(pty_fd)?;

    // SAFETY: stdin stays open for the whole loop; the poller only borrows it.
    let stdin_borrowed = unsafe { BorrowedFd::borrow_raw(stdin_fd) };
    // SAFETY: the pty is owned by the caller for the whole loop, likewise.
    let pty_borrowed = unsafe { BorrowedFd::borrow_raw(pty_fd) };

    // SAFETY: the source is deregistered when the poller is dropped at the end
    // of this function, before the descriptor is closed.
    unsafe {
        poller
            .add(&pty_borrowed, Event::readable(PTY_KEY))
            .map_err(|e| Error::Pty(format!("failed to poll the PTY: {e}")))?;
    }

    let mut stdin_buf = [0u8; 1024];
    let mut pty_buf = [0u8; 4096];
    let mut last_size = crossterm::terminal::size().ok();

    // Regular files and /dev/null cannot be registered for readiness on every
    // platform, and they never block: forward them in one pass instead of
    // polling. Only a stream that can block needs the event loop.
    let mut stdin_flags = None;
    let mut stdin_open = match NonBlocking::set(stdin_fd) {
        Ok(flags) => {
            // SAFETY: as above, deregistered with the poller.
            match unsafe { poller.add(&stdin_borrowed, Event::readable(STDIN_KEY)) } {
                Ok(()) => {
                    stdin_flags = Some(flags);
                    true
                }
                Err(error) => {
                    tracing::debug!(%error, "standard input is not pollable; forwarding it once");
                    drop(flags);
                    forward_all_of_stdin(pty)?;
                    false
                }
            }
        }
        Err(error) => {
            tracing::debug!(%error, "standard input cannot be made non-blocking; forwarding it once");
            forward_all_of_stdin(pty)?;
            false
        }
    };
    let _stdin_flags = stdin_flags;

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| Error::Pty(format!("failed to check child status: {e}")))?
        {
            // Drain whatever the child wrote just before exiting.
            drain(pty, &mut pty_buf);
            return Ok(status);
        }

        events.clear();
        if let Err(error) = poller.wait(&mut events, Some(HOUSEKEEPING_INTERVAL)) {
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Pty(format!(
                "failed to wait for terminal I/O: {error}"
            )));
        }

        // Window changes arrive as SIGWINCH, which this loop does not handle;
        // comparing sizes on the housekeeping tick achieves the same result
        // without installing a signal handler.
        let size = crossterm::terminal::size().ok();
        if size != last_size {
            last_size = size;
            resize_to_terminal(pty);
        }

        for event in events.iter() {
            match event.key {
                STDIN_KEY if stdin_open => {
                    match (&stdin).read(&mut stdin_buf) {
                        Ok(0) => {
                            stdin_open = false;
                            signal_end_of_input(pty);
                        }
                        Ok(n) => {
                            let _ = pty.write_all(&stdin_buf[..n]);
                            let _ = pty.flush();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            stdin_open = false;
                            signal_end_of_input(pty);
                        }
                    }
                    if stdin_open {
                        poller
                            .modify(stdin_borrowed, Event::readable(STDIN_KEY))
                            .map_err(|e| Error::Pty(format!("failed to re-arm stdin: {e}")))?;
                    }
                }
                PTY_KEY => {
                    match pty.read(&mut pty_buf) {
                        // EOF on the pty means the child closed it; wait for the
                        // real status rather than guessing.
                        Ok(0) => {
                            return child
                                .wait()
                                .map_err(|e| Error::Pty(format!("failed to wait: {e}")));
                        }
                        Ok(n) => {
                            let mut stdout = std::io::stdout();
                            let _ = stdout.write_all(&pty_buf[..n]);
                            let _ = stdout.flush();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            return child
                                .wait()
                                .map_err(|e| Error::Pty(format!("failed to wait: {e}")));
                        }
                    }
                    poller
                        .modify(pty_borrowed, Event::readable(PTY_KEY))
                        .map_err(|e| Error::Pty(format!("failed to re-arm the PTY: {e}")))?;
                }
                _ => {}
            }
        }
    }
}

/// Copy all of standard input into the pty, then signal end-of-input.
///
/// Used when standard input is a file or another descriptor that cannot be
/// polled for readiness: such a descriptor never blocks, so one pass is enough.
fn forward_all_of_stdin(pty: &mut Pty) -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| Error::Pty(format!("failed to read standard input: {error}")))?;

    if !input.is_empty() {
        let _ = pty.write_all(&input);
    }
    signal_end_of_input(pty);
    Ok(())
}

/// Tell the child that no more input is coming.
fn signal_end_of_input(pty: &mut Pty) {
    let _ = pty.write_all(&[END_OF_TRANSMISSION]);
    let _ = pty.flush();
}

/// Write out whatever is still buffered in the pty.
fn drain(pty: &mut Pty, buf: &mut [u8]) {
    let mut stdout = std::io::stdout();

    loop {
        match pty.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                let _ = stdout.write_all(&buf[..n]);
                let _ = stdout.flush();
            }
            Err(_) => break,
        }
    }
}
