//! PTY (pseudo-terminal) support for interactive shell sessions

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::path::Path;
use std::process::Child;
use std::time::Duration;

use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use polling::{Event, Events, Poller};

use crate::NetworkPolicy;
use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::network::NetworkProxy;

/// Result of running a command with PTY
pub struct PtyExitStatus {
    success: bool,
}

impl PtyExitStatus {
    pub fn success(&self) -> bool {
        self.success
    }

    pub fn code(&self) -> i32 {
        if self.success { 0 } else { 1 }
    }
}

/// Run a command in a PTY within the sandbox
pub fn run_with_pty<N: NetworkPolicy>(
    config: &SandboxConfigData,
    proxy: Option<&NetworkProxy<N>>,
    ipc_endpoint: Option<&str>,
    program: &str,
    args: &[String],
    envs: &[(String, String)],
    current_dir: Option<&Path>,
) -> Result<PtyExitStatus> {
    let (mut pty, pts) = pty_process::blocking::open()
        .map_err(|e| Error::PtyError(format!("Failed to open PTY: {}", e)))?;

    // Get terminal size and resize PTY
    if let Ok((cols, rows)) = crossterm::terminal::size() {
        let _ = pty.resize(pty_process::Size::new(rows, cols));
    }

    let proxy_port = proxy.map(|proxy| proxy.addr().port()).unwrap_or(0);
    let sbpl_profile = crate::platform::macos::generate_profile(config, proxy_port)?;
    let work_dir = current_dir.unwrap_or(config.working_dir());
    let proxy_url = proxy.map(|proxy| proxy.proxy_url());

    // Build command with chained methods (consuming builder pattern)
    let mut cmd = pty_process::blocking::Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(&sbpl_profile)
        .arg(program);

    for arg in args {
        cmd = cmd.arg(arg);
    }

    cmd = cmd.current_dir(work_dir).env_clear();

    // Pass through standard environment variables
    for var in &["PATH", "TERM", "HOME", "USER", "SHELL", "LANG", "LC_ALL"] {
        if let Ok(val) = std::env::var(var) {
            cmd = cmd.env(var, val);
        }
    }
    if std::env::var("TERM").is_err() {
        cmd = cmd.env("TERM", "xterm-256color");
    }

    for var in config.env_passthrough() {
        if let Ok(val) = std::env::var(var) {
            cmd = cmd.env(var, val);
        }
    }

    if let Some(ref proxy_url) = proxy_url {
        // Set proxy environment variables
        cmd = cmd
            .env("HTTP_PROXY", proxy_url)
            .env("HTTPS_PROXY", proxy_url)
            .env("http_proxy", proxy_url)
            .env("https_proxy", proxy_url);
    }

    for (key, val) in envs {
        cmd = cmd.env(key, val);
    }

    // Inject IPC endpoint and wrappers path for interactive IPC commands
    if let Some(endpoint) = ipc_endpoint {
        let heel_bin = config.working_dir().join(".heel").join("bin");
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", heel_bin.display(), current_path);
        cmd = cmd.env("HEEL_IPC_ENDPOINT", endpoint).env("PATH", new_path);
    }

    // Spawn the child process
    let mut child = cmd
        .spawn(pts)
        .map_err(|e| Error::PtyError(format!("Failed to spawn command: {}", e)))?;

    // Check if stdin is a TTY and enable raw mode
    let stdin_is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    if stdin_is_tty {
        enable_raw_mode()
            .map_err(|e| Error::PtyError(format!("Failed to enable raw mode: {}", e)))?;
    }

    // Run I/O loop
    let result = run_io_loop(&mut pty, &mut child);

    // Restore terminal
    if stdin_is_tty {
        let _ = disable_raw_mode();
    }

    result
}

const STDIN_KEY: usize = 0;
const PTY_KEY: usize = 1;

fn run_io_loop(pty: &mut pty_process::blocking::Pty, child: &mut Child) -> Result<PtyExitStatus> {
    let poller =
        Poller::new().map_err(|e| Error::PtyError(format!("Failed to create poller: {}", e)))?;
    let mut events = Events::new();

    let stdin_fd = std::io::stdin().as_raw_fd();
    let pty_fd = pty.as_raw_fd();

    // Set both FDs to non-blocking
    unsafe {
        let flags = libc::fcntl(stdin_fd, libc::F_GETFL);
        libc::fcntl(stdin_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        let flags = libc::fcntl(pty_fd, libc::F_GETFL);
        libc::fcntl(pty_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // Register FDs with poller
    let stdin_borrowed = unsafe { BorrowedFd::borrow_raw(stdin_fd) };
    let pty_borrowed = unsafe { BorrowedFd::borrow_raw(pty_fd) };

    unsafe {
        #[allow(clippy::needless_borrows_for_generic_args)]
        poller
            .add(&stdin_borrowed, Event::readable(STDIN_KEY))
            .map_err(|e| Error::PtyError(format!("Failed to add stdin to poller: {}", e)))?;
        #[allow(clippy::needless_borrows_for_generic_args)]
        poller
            .add(&pty_borrowed, Event::readable(PTY_KEY))
            .map_err(|e| Error::PtyError(format!("Failed to add PTY to poller: {}", e)))?;
    }

    let mut stdin_buf = [0u8; 1024];
    let mut pty_buf = [0u8; 4096];
    let mut stdin_eof = false;

    loop {
        // Check if child has exited
        match child.try_wait() {
            Ok(Some(status)) => {
                // Drain remaining PTY output
                drain_pty(pty_fd, &mut pty_buf);
                return Ok(PtyExitStatus {
                    success: status.success(),
                });
            }
            Ok(None) => {}
            Err(e) => {
                return Err(Error::PtyError(format!(
                    "Failed to check child status: {}",
                    e
                )));
            }
        }

        events.clear();
        if poller
            .wait(&mut events, Some(Duration::from_millis(100)))
            .is_err()
        {
            continue;
        }

        for event in events.iter() {
            match event.key {
                STDIN_KEY if !stdin_eof => {
                    // Read from stdin and write to PTY
                    let mut stdin = std::io::stdin();
                    match stdin.read(&mut stdin_buf) {
                        Ok(0) => stdin_eof = true,
                        Ok(n) => {
                            let mut pty_file = unsafe { std::fs::File::from_raw_fd(pty_fd) };
                            let _ = pty_file.write_all(&stdin_buf[..n]);
                            let _ = pty_file.flush();
                            std::mem::forget(pty_file);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => stdin_eof = true,
                    }
                    if !stdin_eof {
                        #[allow(clippy::needless_borrows_for_generic_args)]
                        poller
                            .modify(&stdin_borrowed, Event::readable(STDIN_KEY))
                            .ok();
                    }
                }
                PTY_KEY => {
                    let mut pty_file = unsafe { std::fs::File::from_raw_fd(pty_fd) };
                    match pty_file.read(&mut pty_buf) {
                        Ok(0) => {
                            std::mem::forget(pty_file);
                            let status = child
                                .wait()
                                .map_err(|e| Error::PtyError(format!("Failed to wait: {}", e)))?;
                            return Ok(PtyExitStatus {
                                success: status.success(),
                            });
                        }
                        Ok(n) => {
                            std::mem::forget(pty_file);
                            let mut stdout = std::io::stdout();
                            let _ = stdout.write_all(&pty_buf[..n]);
                            let _ = stdout.flush();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::mem::forget(pty_file);
                        }
                        Err(_) => {
                            std::mem::forget(pty_file);
                            let status = child
                                .wait()
                                .map_err(|e| Error::PtyError(format!("Failed to wait: {}", e)))?;
                            return Ok(PtyExitStatus {
                                success: status.success(),
                            });
                        }
                    }
                    #[allow(clippy::needless_borrows_for_generic_args)]
                    poller.modify(&pty_borrowed, Event::readable(PTY_KEY)).ok();
                }
                _ => {}
            }
        }
    }
}

fn drain_pty(pty_fd: i32, buf: &mut [u8]) {
    let mut pty_file = unsafe { std::fs::File::from_raw_fd(pty_fd) };
    let mut stdout = std::io::stdout();

    loop {
        match pty_file.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                let _ = stdout.write_all(&buf[..n]);
                let _ = stdout.flush();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }

    std::mem::forget(pty_file);
}
