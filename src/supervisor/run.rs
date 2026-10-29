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
//! can have reaped. A pid the supervisor lists is held by a live process or by
//! a zombie nobody has reaped, so it has not been handed to an unrelated
//! process. A listed pid is either a child of the supervisor (reaped only by the
//! supervisor, later) or a child of a member that is already stopped (a stopped
//! parent reaps nothing).
//!
//! Signals do not travel by pid. Right after a member is listed, the supervisor
//! opens a pidfd for it (`pidfd_open`, Linux 5.3+), checks through `/proc` that
//! the process behind the pid is still a child of the tree, and sends every
//! later signal through that descriptor (`pidfd_send_signal`). A pidfd names the
//! process it was opened for, so a signal can never reach a process that took
//! the pid after the member died. The only window left is the instant between
//! listing and opening, which the argument above covers.
//!
//! The one case outside that argument is a stopped member that ignores
//! `SIGCHLD`: the kernel reaps its children at exit, so such a child can vanish
//! between being listed and being opened. The answer is then `ESRCH`, which is
//! treated as success because the process is gone.
//!
//! Reaping waits for *any* child (`wait4(-1)`, rustix's `wait`), never
//! `waitpid(None)`: that one is `wait4(0)` and sees only children in the
//! supervisor's own process group, which a `setsid` descendant has left. Taking
//! every child is safe for the same reason as above: every child is the
//! command's.
//!
//! # Wake-ups
//!
//! `SIGCHLD` is blocked and read through a `signalfd`, polled together with
//! the host's control socket. Nothing here sleeps or polls on a timer: the
//! only timeout is the budget a teardown gets to see its processes die.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::{Errno, FdFlags, fcntl_setfd};
use rustix::process::{
    Pid, PidfdFlags, Resource, Rlimit, Signal, WaitOptions, getpid, pidfd_open, pidfd_send_signal,
    set_child_subreaper, setrlimit, wait,
};

use super::procfs;
use super::protocol::{Event, LeftoverProcess, Mode, Request, SpawnFailure, TreeReport};

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
/// Fails if the supervisor cannot be set up, the command cannot be started, the
/// supervisor fails while serving, or the command had not exited when the
/// teardown budget ran out. The host is told which, before this returns, and
/// whatever the supervisor had frozen has been killed.
pub fn run(config: Config) -> io::Result<i32> {
    let Config {
        mode,
        control,
        reap_timeout,
        program,
        args,
    } = config;

    // An ignored `SIGCHLD` survives `exec` and makes the kernel reap children
    // behind our back, which would hide the command's status and every member
    // from `wait`.
    reset_child_signal()?;

    // Descendants must not inherit the host's socket: its closing is how the
    // supervisor learns the host is gone.
    fcntl_setfd(&control, FdFlags::CLOEXEC)?;
    let control = UnixStream::from(control);

    // Before the first child exists, so no orphan can slip past to init.
    set_child_subreaper(Some(getpid()))?;

    // Before the command exists, so a failure here has nothing to clean up: a
    // command spawned first and orphaned by a failing `signalfd` would run
    // unsupervised.
    let (signals, original_mask) = match child_signals() {
        Ok(signals) => signals,
        Err(error) => {
            send(
                &control,
                &Event::Failed(format!("cannot watch for children: {error}")),
            )?;
            send(&control, &Event::Done)?;
            return Err(error);
        }
    };

    let mut command = std::process::Command::new(&program);
    command.args(&args);
    // SAFETY: the closure runs between `fork` and `exec` and only calls
    // `pthread_sigmask`, which is async-signal-safe, on a set captured by copy.
    unsafe {
        command.pre_exec(move || {
            // The mask is inherited across `exec`, and the command must not
            // start with `SIGCHLD` blocked.
            let result = libc::pthread_sigmask(
                libc::SIG_SETMASK,
                &raw const original_mask,
                std::ptr::null_mut(),
            );
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(result))
            }
        });
    }
    let command = match command.spawn() {
        Ok(command) => command,
        Err(error) => {
            // Nothing was started, so there is nothing left to account for.
            send(&control, &Event::SpawnFailed(SpawnFailure::from(&error)))?;
            send(&control, &Event::Done)?;
            return Err(error);
        }
    };

    let mut supervisor = Supervisor {
        mode,
        own: pid_number(getpid()),
        control,
        host_gone: false,
        requests: Vec::new(),
        signals,
        reap_timeout,
        command: command.id(),
        command_status: None,
        frozen: BTreeMap::new(),
        killed: BTreeSet::new(),
    };
    let report = match supervisor.serve() {
        Ok(report) => report,
        Err(error) => {
            // The tree must not outlive the supervisor, whatever went wrong.
            if let Err(teardown) = supervisor.kill_tree(supervisor.reap_timeout) {
                tracing::warn!(%teardown, "the teardown after a failure failed too");
            }
            supervisor.tell(&Event::Failed(error.to_string()));
            supervisor.tell(&Event::Done);
            return Err(error);
        }
    };

    let Some(status) = supervisor.command_status else {
        supervisor.tell(&Event::CommandUnreaped(report));
        supervisor.tell(&Event::Done);
        return Err(io::Error::other(
            "the command had not exited when the teardown budget ran out",
        ));
    };
    send(&supervisor.control, &Event::Done)?;
    Ok(exit_like(status))
}

/// Give `SIGCHLD` its default action, which ignores the signal without the
/// kernel's auto-reaping.
fn reset_child_signal() -> io::Result<()> {
    // SAFETY: an all-zero `sigaction` with `SIG_DFL` as its handler and no
    // flags is a valid value, and the action of `SIGCHLD` may be replaced.
    let result = unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGCHLD, &raw const action, std::ptr::null_mut())
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// End this process the way the command ended.
///
/// A command that dumped core did so itself. Re-raising its signal would dump
/// the supervisor's core too, into the sandbox or to the system's collector
/// under the name `heel`, so core dumps are switched off first: the host sees
/// the same signal, without a core-dump bit, which would otherwise describe the
/// supervisor and not the command.
fn exit_like(status: ExitStatus) -> i32 {
    let Some(signal) = status.signal() else {
        return status.code().unwrap_or(1);
    };
    if status.core_dumped() {
        let none = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        if let Err(error) = setrlimit(Resource::Core, none) {
            tracing::warn!(%error, "could not disable core dumps before re-raising");
        }
    }
    // SAFETY: restoring the default action of a signal and raising it at
    // ourselves touches no memory. The default is restored first because the
    // runtime ignores `SIGPIPE`, which would otherwise swallow the re-raise.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
    // Reached only if raising the signal did not end this process, as for the
    // init of a pid namespace. The shell convention then still tells the host
    // that a signal ended the command.
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
    /// Members stopped by the current teardown and not yet reaped, each with
    /// the pidfd every signal to it goes through.
    frozen: BTreeMap<u32, OwnedFd>,
    /// The members of `frozen` that have been sent `SIGKILL`.
    killed: BTreeSet<u32>,
}

impl Supervisor {
    /// Tell the host something while already failing: a failure to do so is
    /// logged, not allowed to hide the one being reported.
    fn tell(&self, event: &Event) {
        if let Err(error) = send(&self.control, event) {
            tracing::warn!(%error, "could not tell the host");
        }
    }

    /// Run until the tree is gone or has been torn down, returning the report
    /// of the teardown (empty when there was none to make).
    fn serve(&mut self) -> io::Result<TreeReport> {
        loop {
            let descendants = self.reap()?;
            if self.command_status.is_some() {
                match self.mode {
                    Mode::Foreground => {
                        let report = self.kill_tree(self.reap_timeout)?;
                        send(&self.control, &Event::Leftover(report.clone()))?;
                        return Ok(report);
                    }
                    Mode::Background if !descendants => return Ok(TreeReport::default()),
                    Mode::Background => {}
                }
            }
            match self.block_for_wake()? {
                Wake::Child => {}
                Wake::Kill => {
                    let report = self.kill_tree(self.reap_timeout)?;
                    send(&self.control, &Event::Killed(report.clone()))?;
                    return Ok(report);
                }
                Wake::HostGone => return self.kill_tree(self.reap_timeout),
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
            match wait(WaitOptions::NOHANG) {
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
    /// program it execed), and every member still alive when the budget ran
    /// out, frozen or not.
    ///
    /// On an error, everything frozen so far is killed and reaped before the
    /// error is returned: a stopped member left behind would stay stopped
    /// under init for good.
    fn kill_tree(&mut self, budget: Duration) -> io::Result<TreeReport> {
        let deadline = Instant::now() + budget;
        match self.teardown(deadline) {
            Ok(report) => Ok(report),
            Err(error) => {
                self.abort_freeze(deadline);
                Err(error)
            }
        }
    }

    /// Kill and reap what a failed teardown had frozen, within `deadline`. A
    /// failure here is logged: the caller returns the error that led here.
    fn abort_freeze(&mut self, deadline: Instant) {
        for (&pid, fd) in &self.frozen {
            if let Err(error) = signal(fd, Signal::KILL) {
                tracing::warn!(pid, %error, "could not kill a frozen member");
            }
        }
        loop {
            match self.reap() {
                Ok(true) => {}
                Ok(false) => return,
                Err(error) => {
                    tracing::warn!(%error, "could not reap after a failed teardown");
                    return;
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return;
            };
            if let Err(error) = self.block_for_child(remaining) {
                tracing::warn!(%error, "could not wait after a failed teardown");
                return;
            }
        }
    }

    fn teardown(&mut self, deadline: Instant) -> io::Result<TreeReport> {
        let mut killed = Vec::new();
        loop {
            self.freeze(deadline)?;

            let fresh: Vec<u32> = self
                .frozen
                .keys()
                .filter(|pid| !self.killed.contains(pid))
                .copied()
                .collect();
            killed.extend(describe(fresh.iter().copied())?);
            for pid in &fresh {
                if let Some(fd) = self.frozen.get(pid) {
                    signal(fd, Signal::KILL)?;
                }
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
                    // Members the freeze never reached are alive too, so the
                    // survivors come from the table, not from `frozen`.
                    return Ok(TreeReport {
                        killed,
                        survivors: self.live_members()?,
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
                    !self.frozen.contains_key(&entry.pid) && self.is_member_parent(entry.ppid)
                })
                .map(|entry| entry.pid)
                .collect();
            if fresh.is_empty() {
                return Ok(());
            }
            for pid in fresh {
                let Some(fd) = self.open_member(pid)? else {
                    continue;
                };
                signal(&fd, Signal::STOP)?;
                self.frozen.insert(pid, fd);
            }
            if Instant::now() >= deadline {
                return Ok(());
            }
        }
    }

    /// Whether a process with parent `ppid` belongs to the tree: its parent is
    /// this process or a stopped member.
    fn is_member_parent(&self, ppid: u32) -> bool {
        ppid == self.own || self.frozen.contains_key(&ppid)
    }

    /// Open a pidfd for the member `pid` that was just listed, or `None` when
    /// it is gone or is no longer a child of the tree.
    ///
    /// The check after the open is what ties the descriptor to a member: the
    /// descriptor pins one process, and `/proc` read after it was opened still
    /// shows that process unless it has been reaped, in which case the entry is
    /// missing or its parent is not ours.
    fn open_member(&self, pid: u32) -> io::Result<Option<OwnedFd>> {
        let Some(raw) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
            return Err(io::Error::other(format!("{pid} is not a process id")));
        };
        let fd = match pidfd_open(raw, PidfdFlags::empty()) {
            Ok(fd) => fd,
            Err(Errno::SRCH) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(procfs::read(pid)?
            .is_some_and(|entry| self.is_member_parent(entry.ppid))
            .then_some(fd))
    }

    /// Every running process whose chain of parents leads to this one.
    fn live_members(&self) -> io::Result<Vec<LeftoverProcess>> {
        let table = procfs::snapshot()?;
        let parents: HashMap<u32, u32> =
            table.iter().map(|entry| (entry.pid, entry.ppid)).collect();
        let descends = |start: u32| {
            let mut pid = start;
            // A chain longer than the table is a loop.
            for _ in 0..=parents.len() {
                match parents.get(&pid) {
                    Some(&parent) if parent == self.own => return true,
                    Some(&parent) => pid = parent,
                    None => return false,
                }
            }
            false
        };
        Ok(table
            .iter()
            .filter(|entry| !entry.is_zombie() && descends(entry.pid))
            .map(|entry| LeftoverProcess {
                pid: entry.pid,
                name: entry.name.clone(),
            })
            .collect())
    }

    fn has_unfrozen_child(&self) -> io::Result<bool> {
        Ok(procfs::snapshot()?
            .iter()
            .any(|entry| entry.ppid == self.own && !self.frozen.contains_key(&entry.pid)))
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
/// pending, with the signal mask as it was before.
fn child_signals() -> io::Result<(File, libc::sigset_t)> {
    let mut set = MaybeUninit::<libc::sigset_t>::uninit();
    let mut original = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: `set` is initialised by `sigemptyset` before anything reads it,
    // `original` is filled in by `pthread_sigmask` before it is read, and every
    // call below is given a valid pointer.
    unsafe {
        libc::sigemptyset(set.as_mut_ptr());
        libc::sigaddset(set.as_mut_ptr(), libc::SIGCHLD);
        let set = set.assume_init();
        let blocked = libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, original.as_mut_ptr());
        if blocked != 0 {
            return Err(io::Error::from_raw_os_error(blocked));
        }
        let original = original.assume_init();
        let fd = libc::signalfd(-1, &raw const set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `signalfd` returned a new descriptor that nothing else owns.
        Ok((File::from_raw_fd(fd), original))
    }
}

/// Send `signal` to the member behind `pidfd`. A member that is already gone
/// is not an error: that is what the signal was for.
fn signal(pidfd: &OwnedFd, signal: Signal) -> io::Result<()> {
    match pidfd_send_signal(pidfd, signal) {
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
