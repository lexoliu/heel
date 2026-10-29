//! `heel supervise`: the process that owns one command's whole tree.
//!
//! It runs inside the sandbox as the command's root process, so everything it
//! does is inside the sandbox's own limits.
//!
//! # Why no member is reaped before it is killed
//!
//! The supervisor is a child subreaper, so every process of the tree that loses
//! its parent is reparented to it, and a process that has exited stays a zombie
//! holding its pid until its parent waits for it. The supervisor waits only
//! outside a teardown's freeze, and a teardown signals only pids that no one
//! can have reaped. That is the property every signal below relies on: a pid
//! the supervisor signals is held by a live process or by a zombie nobody has
//! reaped, so it has not been handed to an unrelated process, and membership
//! needs no identity check. A signalled pid is either a child of the supervisor
//! (reaped only by the supervisor, later) or a child of a member that is already
//! stopped (a stopped parent reaps nothing).
//!
//! The one case outside this argument is a stopped member that ignores
//! `SIGCHLD`: the kernel reaps its children at exit, so such a child can vanish
//! between being listed and being signalled. The answer is then `ESRCH`, which
//! is treated as success because the process is gone, unless the pid space
//! wraps inside that one pass.
//!
//! `waitpid(-1)` is safe for the same reason: every child is the command's.
//!
//! # Wake-ups
//!
//! `SIGCHLD` is blocked and read through a `signalfd`, polled together with
//! the host's control socket. Nothing here sleeps or polls on a timer: the
//! only timeout is the budget a teardown gets to see its processes die.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::{Errno, FdFlags, fcntl_setfd};
use rustix::process::{
    Pid, Signal, WaitOptions, getpid, kill_process, set_child_subreaper, waitpid,
};

use super::procfs;
use super::protocol::{Event, LeftoverProcess, Mode, Request, TreeReport};

/// What `heel supervise` was asked to run.
#[derive(Debug)]
pub struct Config {
    /// How long the supervisor lives.
    pub mode: Mode,
    /// The socket to the host, inherited from it.
    pub control: OwnedFd,
    /// The budget a teardown gets to see the processes it killed exit.
    pub reap_timeout: Duration,
    /// The command to run.
    pub program: String,
    /// The command's arguments.
    pub args: Vec<String>,
}

/// Supervise a command until its tree is gone, returning the exit code to
/// exit with.
///
/// Must be called before the process starts any other thread: the `SIGCHLD`
/// that wakes it is process-directed, and a thread that has not blocked it
/// could take the signal instead.
///
/// The command's status is passed on unchanged: a command killed by a signal
/// makes this process die by the same signal, so the code returned is only for
/// a signal that cannot kill (`128 + signal`, the shell convention).
///
/// # Errors
///
/// Fails if the supervisor cannot be set up, the command cannot be started, or
/// the command had not exited when the teardown budget ran out.
pub fn run(config: Config) -> io::Result<i32> {
    let Config {
        mode,
        control,
        reap_timeout,
        program,
        args,
    } = config;

    // Descendants must not inherit the host's socket: its closing is how the
    // supervisor learns the host is gone.
    fcntl_setfd(&control, FdFlags::CLOEXEC)?;
    let control = UnixStream::from(control);

    // Before the first child exists, so no orphan can slip past to init.
    set_child_subreaper(Some(getpid()))?;

    let command = match std::process::Command::new(&program).args(&args).spawn() {
        Ok(command) => command,
        Err(error) => {
            // Nothing was started, so there is nothing left to account for.
            send(&control, &Event::Done)?;
            return Err(error);
        }
    };

    // After the command was spawned: the signal mask is inherited across
    // `exec`, and the command must not start with `SIGCHLD` blocked. A child
    // that exits before the mask is set is found by the first `reap`, which
    // runs before anything waits.
    let mut supervisor = Supervisor {
        mode,
        own: pid_number(getpid()),
        control,
        host_gone: false,
        requests: Vec::new(),
        signals: child_signals()?,
        reap_timeout,
        command: command.id(),
        command_status: None,
        frozen: BTreeSet::new(),
        killed: BTreeSet::new(),
    };
    supervisor.serve()?;
    send(&supervisor.control, &Event::Done)?;

    let status = supervisor.command_status.ok_or_else(|| {
        io::Error::other("the command had not exited when the teardown budget ran out")
    })?;
    Ok(exit_like(status))
}

/// End this process the way the command ended.
fn exit_like(status: ExitStatus) -> i32 {
    let Some(signal) = status.signal() else {
        return status.code().unwrap_or(1);
    };
    // SAFETY: restoring the default action of a signal and raising it at
    // ourselves touches no memory. The default is restored first because the
    // runtime ignores `SIGPIPE`, which would otherwise swallow the re-raise.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
    // Reached only for a signal whose default is not to terminate.
    128 + signal
}

fn pid_number(pid: Pid) -> u32 {
    pid.as_raw_nonzero().get().unsigned_abs()
}

/// What woke the supervisor.
enum Wake {
    /// A child changed state.
    Child,
    /// The host asked for the tree to be killed.
    Kill,
    /// The host closed its end.
    HostGone,
}

struct Supervisor {
    mode: Mode,
    own: u32,
    control: UnixStream,
    host_gone: bool,
    /// Bytes of a request not yet complete.
    requests: Vec<u8>,
    /// Becomes readable when a child changes state.
    signals: File,
    reap_timeout: Duration,
    command: u32,
    command_status: Option<ExitStatus>,
    /// Members stopped by the current teardown and not yet reaped.
    frozen: BTreeSet<u32>,
    /// The members of `frozen` that have been sent `SIGKILL`.
    killed: BTreeSet<u32>,
}

impl Supervisor {
    /// Run until the tree is gone or has been torn down.
    fn serve(&mut self) -> io::Result<()> {
        loop {
            let descendants = self.reap()?;
            if self.command_status.is_some() {
                match self.mode {
                    Mode::Foreground => {
                        let report = self.kill_tree(self.reap_timeout)?;
                        return send(&self.control, &Event::Leftover(report));
                    }
                    Mode::Background if !descendants => return Ok(()),
                    Mode::Background => {}
                }
            }
            match self.block_for_wake()? {
                Wake::Child => {}
                Wake::Kill => {
                    let report = self.kill_tree(self.reap_timeout)?;
                    return send(&self.control, &Event::Killed(report));
                }
                Wake::HostGone => {
                    self.kill_tree(self.reap_timeout)?;
                    return Ok(());
                }
            }
        }
    }

    /// Block until a child changes state or the host says something.
    fn block_for_wake(&mut self) -> io::Result<Wake> {
        loop {
            let (child, control) = {
                let signals = self.signals.as_fd();
                let mut fds = vec![PollFd::new(&signals, PollFlags::IN)];
                if !self.host_gone {
                    fds.push(PollFd::new(&self.control, PollFlags::IN));
                }
                match poll(&mut fds, None) {
                    Ok(_) => {}
                    Err(Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                }
                let ready = |fd: Option<&PollFd<'_>>| fd.is_some_and(|fd| !fd.revents().is_empty());
                (ready(fds.first()), ready(fds.get(1)))
            };
            if child {
                drain_signals(&self.signals)?;
            }
            if control && let Some(wake) = self.read_control()? {
                return Ok(wake);
            }
            if child {
                return Ok(Wake::Child);
            }
        }
    }

    /// Read what the host sent, returning what it asks for.
    fn read_control(&mut self) -> io::Result<Option<Wake>> {
        let mut chunk = [0_u8; 512];
        let read = (&self.control).read(&mut chunk)?;
        if read == 0 {
            self.host_gone = true;
            return Ok(Some(Wake::HostGone));
        }
        self.requests.extend_from_slice(&chunk[..read]);
        if let Some(end) = self.requests.iter().position(|&byte| byte == b'\n') {
            let line: Vec<u8> = self.requests.drain(..=end).collect();
            let Request::Kill = serde_json::from_slice(&line)?;
            return Ok(Some(Wake::Kill));
        }
        Ok(None)
    }

    /// Reap every child that has exited, recording the command's status.
    ///
    /// Returns whether any child is left.
    fn reap(&mut self) -> io::Result<bool> {
        loop {
            match waitpid(None, WaitOptions::NOHANG) {
                Ok(Some((pid, status))) => {
                    let pid = pid_number(pid);
                    // The pid is free again, to be handed to a new member.
                    self.frozen.remove(&pid);
                    self.killed.remove(&pid);
                    if pid == self.command && self.command_status.is_none() {
                        self.command_status = Some(ExitStatus::from_raw(status.as_raw()));
                    }
                }
                Ok(None) => return Ok(true),
                Err(Errno::CHILD) => return Ok(false),
                Err(Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Freeze the tree, `SIGKILL` it and reap it until no child is left or
    /// `budget` is spent.
    ///
    /// The report names every process that was running when the tree was
    /// frozen (read then, so a process that had only just forked shows the
    /// program it execed), and every one still alive when the budget ran out.
    fn kill_tree(&mut self, budget: Duration) -> io::Result<TreeReport> {
        let deadline = Instant::now() + budget;
        let mut killed = Vec::new();
        loop {
            self.freeze(deadline)?;

            let fresh: Vec<u32> = self.frozen.difference(&self.killed).copied().collect();
            killed.extend(describe(fresh.iter().copied())?);
            for &pid in &fresh {
                signal(pid, Signal::KILL)?;
            }
            self.killed.extend(fresh);

            loop {
                if !self.reap()? {
                    return Ok(TreeReport {
                        killed,
                        survivors: Vec::new(),
                    });
                }
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return Ok(TreeReport {
                        killed,
                        survivors: describe(self.frozen.iter().copied())?,
                    });
                };
                // A process forked in the instant before its parent stopped
                // is a child of ours once the parent is dead: freeze again.
                if self.has_unfrozen_child()? {
                    break;
                }
                self.block_for_child(remaining)?;
            }
        }
    }

    /// `SIGSTOP` the tree until a pass finds no member that is not stopped.
    ///
    /// A member is a child of this process or a child of a stopped member, so
    /// the tree is stopped from the top down: a stopped process forks nothing
    /// and reaps nothing, and everything it had already forked is visible in
    /// the next pass. A pass that finds nothing new proves the tree is frozen:
    /// an unstopped member would be a descendant whose chain to this process
    /// has an unstopped link, and the topmost link is a direct child, which
    /// every pass picks up. The module documentation says why the pids
    /// signalled here cannot belong to anyone else.
    fn freeze(&mut self, deadline: Instant) -> io::Result<()> {
        loop {
            let fresh: Vec<u32> = procfs::snapshot()?
                .into_iter()
                .filter(|entry| {
                    !self.frozen.contains(&entry.pid)
                        && (entry.ppid == self.own || self.frozen.contains(&entry.ppid))
                })
                .map(|entry| entry.pid)
                .collect();
            if fresh.is_empty() {
                return Ok(());
            }
            for pid in fresh {
                signal(pid, Signal::STOP)?;
                self.frozen.insert(pid);
            }
            if Instant::now() >= deadline {
                return Ok(());
            }
        }
    }

    fn has_unfrozen_child(&self) -> io::Result<bool> {
        Ok(procfs::snapshot()?
            .iter()
            .any(|entry| entry.ppid == self.own && !self.frozen.contains(&entry.pid)))
    }

    /// Block for up to `remaining` until a child changes state.
    fn block_for_child(&self, remaining: Duration) -> io::Result<()> {
        let timeout = Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: remaining.subsec_nanos().into(),
        };
        let signals = self.signals.as_fd();
        let mut fds = [PollFd::new(&signals, PollFlags::IN)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(Errno::INTR) => Ok(()),
            Ok(_) => drain_signals(&self.signals),
            Err(error) => Err(error.into()),
        }
    }
}

/// Tell the host something. A host that has gone away is told nothing.
fn send(control: &UnixStream, event: &Event) -> io::Result<()> {
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    let mut control = control;
    match control.write_all(&line) {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// Consume the pending `SIGCHLD` notifications.
fn drain_signals(signals: &File) -> io::Result<()> {
    let mut signals = signals;
    let mut info = [0_u8; 128];
    loop {
        match signals.read(&mut info) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Block `SIGCHLD` and return a descriptor that becomes readable when one is
/// pending.
fn child_signals() -> io::Result<File> {
    let mut set = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: `set` is initialised by `sigemptyset` before anything reads it,
    // and every call below is given a valid pointer to it.
    unsafe {
        libc::sigemptyset(set.as_mut_ptr());
        libc::sigaddset(set.as_mut_ptr(), libc::SIGCHLD);
        let set = set.assume_init();
        let blocked = libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
        if blocked != 0 {
            return Err(io::Error::from_raw_os_error(blocked));
        }
        let fd = libc::signalfd(-1, &raw const set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `signalfd` returned a new descriptor that nothing else owns.
        Ok(File::from_raw_fd(fd))
    }
}

/// Send `signal` to a member. A member that is already gone is not an error:
/// that is what the signal was for.
fn signal(pid: u32, signal: Signal) -> io::Result<()> {
    let pid = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| io::Error::other(format!("{pid} is not a process id")))?;
    match kill_process(pid, signal) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Name the processes among `pids` that are still running.
fn describe(pids: impl Iterator<Item = u32>) -> io::Result<Vec<LeftoverProcess>> {
    let mut described = Vec::new();
    for pid in pids {
        if let Some(entry) = procfs::read(pid)?
            && !entry.is_zombie()
        {
            described.push(LeftoverProcess {
                pid,
                name: entry.name,
            });
        }
    }
    Ok(described)
}
