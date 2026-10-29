//! The broker: a supervisor that performs, for the sandboxed process, the calls
//! the host protection policies have to judge.
//!
//! Landlock cannot express "everything below here except this", and a rule it
//! has cannot be added to a process that is already restricted. So the sandbox's
//! own Landlock layer holds no right to change the filesystem at all, and every
//! call that creates, changes, removes or writes is stopped by seccomp and sent
//! here as a user notification. The broker judges it against the policy, by the
//! real path and inode it resolves to through directories it holds, performs it
//! itself, and hands the result back: the return value, or for an open a
//! descriptor installed in the caller.
//!
//! Two arrangements exist:
//!
//! * with a read or write denylist the full broker serves file calls, `connect`
//!   and `bind`, and the sandbox's Landlock layer is the broker's with writes
//!   taken away and the denied trees carved out;
//! * without one, a sandbox that may reach the network gets a broker for
//!   `connect` alone, which is what limits outbound TCP to the proxy's loopback
//!   address, a restriction Landlock can only express for a port.
//!
//! Every sandboxed process is forked from the launcher thread, whose Landlock
//! domain is the broker's, so the sandbox's domain is a descendant of it and
//! Landlock lets the broker read the memory of, and take descriptors from, the
//! processes it serves.

mod check;
mod filter;
mod net;
mod notify;
mod ops;
mod pool;
mod resolve;
pub(crate) mod sink;

use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use landlock::Access as _;
use libc::sock_filter;

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::platform::linux::landlock_rules::{
    self, Planned, PreparedRuleset, REQUIRED_ABI, without_writes,
};

use check::Guard;
use filter::{Coverage, Syscall};
use notify::{Listener, Reply};
use ops::{Call, Errno};
use pool::Pool;
use resolve::Caller;
use sink::DenialSink;

#[cfg(target_arch = "x86_64")]
pub(crate) use filter::x32_refusal;

/// The most threads that serve one sandbox, however many calls block.
const MAX_WORKERS: usize = 256;

/// What every thread that serves a sandbox shares.
#[derive(Debug)]
pub(crate) struct Shared {
    guard: Guard,
    pool: Option<Pool>,
    sink: Arc<DenialSink>,
    rename_lock: RwLock<()>,
    proxy_port: Option<u16>,
    sync_wake_up: bool,
}

/// The lock a call holds while it is served.
pub(crate) enum Held<'a> {
    /// Taken by a call that names no file.
    None,
    /// Taken by every call but a rename.
    Shared(#[allow(dead_code)] RwLockReadGuard<'a, ()>),
    /// Taken by a rename, so that no name changes under a call that checked it.
    Exclusive(#[allow(dead_code)] RwLockWriteGuard<'a, ()>),
}

impl Shared {
    /// Lock for serving `syscall`.
    pub(crate) fn hold_for(&self, syscall: Syscall) -> Held<'_> {
        // A connect to an inet address names no file and can take long, so it
        // must not hold up the renames that wait for the write side.
        if syscall == Syscall::Connect {
            return Held::None;
        }
        if matches!(
            syscall,
            Syscall::Rename | Syscall::Renameat | Syscall::Renameat2
        ) {
            Held::Exclusive(
                self.rename_lock
                    .write()
                    .unwrap_or_else(PoisonError::into_inner),
            )
        } else {
            Held::Shared(
                self.rename_lock
                    .read()
                    .unwrap_or_else(PoisonError::into_inner),
            )
        }
    }

    /// The shared side of the lock, for a call that turns out to name a file.
    pub(crate) fn read_lock(&self) -> Held<'_> {
        self.hold_for(Syscall::Open)
    }

    /// Whether a connection to `ip:port` is the one the sandbox may make.
    pub(crate) fn proxy_reachable(&self, ip: Ipv4Addr, port: u16) -> bool {
        ip == crate::network::PROXY_ADDRESS && self.proxy_port == Some(port)
    }
}

/// The listener of one sandboxed process tree and the threads serving it.
#[derive(Debug)]
struct Serving {
    listener: Listener,
    shared: Arc<Shared>,
    idle: AtomicUsize,
    threads: AtomicUsize,
    base: usize,
}

/// What a handler needs to serve one call.
pub(crate) struct Context<'a> {
    serving: &'a Arc<Serving>,
}

impl Context<'_> {
    pub(crate) fn shared(&self) -> &Shared {
        &self.serving.shared
    }

    /// Make sure another thread is listening before this one blocks in a call
    /// that can take long, so that it never holds up the others.
    pub(crate) fn ensure_spare_worker(&self) {
        if self.serving.idle.load(Ordering::Acquire) == 0
            && self.serving.threads.load(Ordering::Acquire) < MAX_WORKERS
            && let Err(error) = spawn_worker(self.serving)
        {
            tracing::error!(%error, "broker: cannot start a worker");
        }
    }
}

fn spawn_worker(serving: &Arc<Serving>) -> io::Result<()> {
    serving.threads.fetch_add(1, Ordering::AcqRel);
    serving.idle.fetch_add(1, Ordering::AcqRel);
    let worker = Arc::clone(serving);
    let spawned = std::thread::Builder::new()
        .name("heel-broker".to_owned())
        .spawn(move || work(&worker));
    if let Err(error) = spawned {
        serving.threads.fetch_sub(1, Ordering::AcqRel);
        serving.idle.fetch_sub(1, Ordering::AcqRel);
        return Err(error);
    }
    Ok(())
}

fn work(serving: &Arc<Serving>) {
    // A thread of its own working directory and file creation mask, so serving
    // one call never changes what another sees.
    // SAFETY: `unshare(CLONE_FS)` takes a flag and touches only this thread.
    if unsafe { libc::unshare(libc::CLONE_FS) } != 0 {
        tracing::error!(error = %io::Error::last_os_error(), "broker: unshare(CLONE_FS) failed");
        serving.threads.fetch_sub(1, Ordering::AcqRel);
        serving.idle.fetch_sub(1, Ordering::AcqRel);
        return;
    }
    loop {
        match serving.listener.recv() {
            Ok(notification) => {
                serving.idle.fetch_sub(1, Ordering::AcqRel);
                serve(serving, &notification);
                let idle = serving.idle.fetch_add(1, Ordering::AcqRel) + 1;
                if serving.threads.load(Ordering::Acquire) > serving.base && idle > 1 {
                    break;
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => {}
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                if serving.listener.is_orphaned() {
                    break;
                }
            }
            Err(error) => {
                tracing::error!(%error, "broker: receive failed");
                break;
            }
        }
    }
    serving.idle.fetch_sub(1, Ordering::AcqRel);
    serving.threads.fetch_sub(1, Ordering::AcqRel);
}

fn serve(serving: &Arc<Serving>, notification: &libc::seccomp_notif) {
    let listener = &serving.listener;
    let id = notification.id;
    let Some(syscall) = filter::classify(notification.data.nr) else {
        tracing::error!(
            nr = notification.data.nr,
            "broker: a call the filter does not name"
        );
        let _ = listener.reply(id, Reply::Errno(libc::ENOSYS));
        return;
    };
    let caller = Caller::new(listener, id, notification.pid);
    let call = Call {
        syscall,
        args: notification.data.args,
        caller: &caller,
    };
    let context = Context { serving };
    let reply = match ops::serve(&context, &call) {
        Ok(reply) => reply,
        Err(Errno(errno)) => Reply::Errno(errno),
    };
    if let Err(error) = listener.reply(id, reply)
        && error.raw_os_error() != Some(libc::ENOENT)
    {
        tracing::debug!(%error, "broker: reply failed");
    }
}

/// A process to start through the launcher.
struct Job {
    command: Command,
    listener_socket: OwnedFd,
    reply: SyncSender<io::Result<Child>>,
}

/// The broker of one sandbox.
pub(crate) struct Broker {
    program: Vec<sock_filter>,
    jobs: Sender<Job>,
}

/// What the child runs between `fork` and `exec` to hand its listener over.
pub(crate) struct ChildHook {
    program: Vec<sock_filter>,
    socket: OwnedFd,
}

impl ChildHook {
    /// Install the notification filter and send its listener to the broker.
    /// Called from `pre_exec`, after the sandbox's Landlock layer.
    pub(crate) fn install(&self) -> io::Result<()> {
        // SAFETY: both `prctl` calls take integers by value.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let program = libc::sock_fprog {
            len: u16::try_from(self.program.len())
                .map_err(|_| io::Error::other("filter too long"))?,
            filter: self.program.as_ptr().cast_mut(),
        };
        let flags =
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER | libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
        // SAFETY: `program` points at `len` instructions that outlive the call.
        let listener = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                flags,
                &raw const program,
            )
        };
        if listener < 0 {
            return Err(io::Error::last_os_error());
        }
        let listener = listener as RawFd;
        let sent = notify::send_fd(self.socket.as_raw_fd(), listener);
        // SAFETY: `listener` was returned by the call above and is not used again.
        unsafe { libc::close(listener) };
        sent
    }
}

/// `/proc/sys/kernel/yama/ptrace_scope`, when Yama is loaded.
const YAMA_SCOPE: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// The highest `kernel.yama.ptrace_scope` under which a parent can read its child.
const MAX_PTRACE_SCOPE: u8 = 1;

/// Refuse a kernel whose Yama setting stops a parent from reading its child.
fn check_ptrace_scope() -> Result<()> {
    match std::fs::read_to_string(YAMA_SCOPE) {
        Ok(text) => parse_ptrace_scope(&text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::path(YAMA_SCOPE, error)),
    }
}

/// Judge the contents of [`YAMA_SCOPE`].
fn parse_ptrace_scope(text: &str) -> Result<()> {
    let scope: u8 = text
        .trim()
        .parse()
        .map_err(|_| Error::InitFailed(format!("cannot read {YAMA_SCOPE}: {}", text.trim())))?;
    if scope > MAX_PTRACE_SCOPE {
        return Err(Error::PtraceScopeTooStrict {
            scope,
            max: MAX_PTRACE_SCOPE,
        });
    }
    Ok(())
}

impl Broker {
    /// The broker a configuration needs, if it needs one.
    pub(crate) fn new(
        config: &SandboxConfigData,
        proxy_port: Option<u16>,
        sink: Arc<DenialSink>,
    ) -> Result<Option<(Self, PreparedRuleset)>> {
        let protected = landlock_rules::protected_patterns(config);
        let denylists = config.read_denylist().is_some()
            || config.write_denylist().is_some()
            || !protected.is_empty();
        if !denylists && proxy_port.is_none() {
            return Ok(None);
        }
        notify::check_sizes()?;
        check_ptrace_scope()?;

        let abi = REQUIRED_ABI;
        let (sandbox_ruleset, guard, pool, broker_rules, coverage) = if denylists {
            let plan = landlock_rules::plan(config);
            let mut denied: Vec<PathBuf> = match config.read_denylist() {
                Some(read) => {
                    let resolved = read.resolve()?;
                    resolved
                        .trees
                        .into_iter()
                        .filter(|tree| !resolved.sockets.contains(tree))
                        .collect()
                }
                None => Vec::new(),
            };
            denied.extend(landlock_rules::find_protected(&plan, &protected));
            let carved = landlock_rules::carve(plan.clone(), &denied, abi)?;
            let sandbox_rules = without_writes(&carved.rules, abi);
            let mut sandbox_ruleset = landlock_rules::instantiate(&sandbox_rules, proxy_port, abi)?;
            let reads = landlock_rules::read_rights(abi);
            let pool = if carved.ancestors.is_empty() {
                None
            } else {
                Some(Pool::create(
                    config.inode_pool(),
                    &carved.ancestors,
                    &mut |fd, access| {
                        let access = access & reads;
                        if access.is_empty() {
                            Ok(())
                        } else {
                            sandbox_ruleset.add_inode(fd, access, abi)
                        }
                    },
                )?)
            };
            let ancestors: HashSet<PathBuf> = carved
                .ancestors
                .iter()
                .map(|ancestor| ancestor.path.clone())
                .collect();
            let pool_dirs = pool.as_ref().map_or_else(Vec::new, Pool::directories);
            let guard = Guard::new(config, ancestors, pool_dirs.clone())?;

            let mut broker_rules = plan;
            for directory in pool_dirs {
                broker_rules.push(Planned {
                    path: directory,
                    access: landlock::AccessFs::from_all(abi),
                    required: true,
                    grant: false,
                });
            }
            let coverage = Coverage {
                files: true,
                reads: guard.watches_reads(),
            };
            (sandbox_ruleset, guard, pool, Some(broker_rules), coverage)
        } else {
            let guard = Guard::new(config, HashSet::new(), Vec::new())?;
            (
                landlock_rules::build_ruleset(config, proxy_port)?,
                guard,
                None,
                None,
                Coverage {
                    files: false,
                    reads: false,
                },
            )
        };

        let program = filter::build(coverage)?;
        let shared = Arc::new(Shared {
            guard,
            pool,
            sink,
            rename_lock: RwLock::new(()),
            proxy_port,
            sync_wake_up: config.broker_sync_wake_up(),
        });
        let broker_ruleset = broker_rules
            .map(|rules| landlock_rules::instantiate(&rules, proxy_port, abi))
            .transpose()?;

        let (jobs, queue) = channel();
        let (ready, started) = sync_channel(1);
        let launcher_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("heel-launcher".to_owned())
            .spawn(move || launch(broker_ruleset, &queue, &launcher_shared, &ready))
            .map_err(|error| Error::InitFailed(format!("cannot start the broker: {error}")))?;
        started
            .recv()
            .map_err(|_| Error::InitFailed("the broker's launcher exited".to_owned()))?
            .map_err(|error| Error::InitFailed(format!("cannot restrict the broker: {error}")))?;

        tracing::info!(full = denylists, "broker started");
        Ok(Some((Self { program, jobs }, sandbox_ruleset)))
    }

    /// What a command needs to be served by this broker: the hook for its child
    /// and the end of the channel the broker receives the listener on.
    pub(crate) fn prepare(&self) -> io::Result<(ChildHook, OwnedFd)> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `socketpair` fills two descriptors.
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors are new and owned by nothing else.
        let (parent, child) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        Ok((
            ChildHook {
                program: self.program.clone(),
                socket: child,
            },
            parent,
        ))
    }

    /// Start `command` from the launcher thread and begin serving it.
    pub(crate) fn spawn(&self, command: Command, listener_socket: OwnedFd) -> io::Result<Child> {
        let (reply, result) = sync_channel(1);
        self.jobs
            .send(Job {
                command,
                listener_socket,
                reply,
            })
            .map_err(|_| io::Error::other("the broker's launcher exited"))?;
        result
            .recv()
            .map_err(|_| io::Error::other("the broker's launcher exited"))?
    }
}

/// The launcher thread: restricted once, then forking every sandboxed process.
fn launch(
    ruleset: Option<PreparedRuleset>,
    jobs: &Receiver<Job>,
    shared: &Arc<Shared>,
    ready: &SyncSender<io::Result<()>>,
) {
    let restricted = match ruleset {
        Some(ruleset) => ruleset.restrict_self(),
        None => Ok(()),
    };
    let failed = restricted.is_err();
    let _ = ready.send(restricted);
    if failed {
        return;
    }
    let workers = std::thread::available_parallelism().map_or(2, usize::from);
    for mut job in jobs {
        let outcome = job.command.spawn().and_then(|mut child| {
            let started = notify::recv_fd(job.listener_socket.as_raw_fd()).and_then(|fd| {
                let listener = Listener::new(fd);
                if shared.sync_wake_up {
                    listener.set_sync_wake_up()?;
                }
                let serving = Arc::new(Serving {
                    listener,
                    shared: Arc::clone(shared),
                    idle: AtomicUsize::new(0),
                    threads: AtomicUsize::new(0),
                    base: workers,
                });
                for _ in 0..workers {
                    spawn_worker(&serving)?;
                }
                Ok(())
            });
            match started {
                Ok(()) => Ok(child),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    Err(error)
                }
            }
        });
        let _ = job.reply.send(outcome);
    }
}

#[cfg(test)]
mod ptrace_scope_tests {
    use super::*;

    #[test]
    fn accepts_scopes_the_broker_works_under() {
        for text in ["0\n", "1\n"] {
            parse_ptrace_scope(text).unwrap();
        }
    }

    #[test]
    fn rejects_stricter_scopes_with_a_typed_error() {
        let error = parse_ptrace_scope("2\n").unwrap_err();
        assert!(matches!(
            error,
            Error::PtraceScopeTooStrict { scope: 2, max: 1 }
        ));
        let message = error.to_string();
        assert!(
            message.contains("kernel.yama.ptrace_scope is 2"),
            "{message}"
        );
        assert!(message.contains("needs 1 or lower"), "{message}");
        assert!(matches!(
            parse_ptrace_scope("3").unwrap_err(),
            Error::PtraceScopeTooStrict { scope: 3, .. }
        ));
    }

    #[test]
    fn garbage_is_not_a_scope() {
        assert!(matches!(
            parse_ptrace_scope("lots").unwrap_err(),
            Error::InitFailed(_)
        ));
    }
}
