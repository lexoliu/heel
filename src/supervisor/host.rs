//! The host's side of a supervised command.

use std::io::{BufRead, BufReader, Write};
use std::marker::PhantomData;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use blocking::unblock;

use crate::error::{Error, Result};
use crate::platform::Child;

use super::protocol::{Event, Mode, Request, SpawnFailure, TreeReport, reap_timeout_argument};

mod sealed {
    pub trait Sealed {}
}

/// How a command is supervised, which decides what waiting for it returns.
pub trait Supervision: sealed::Sealed {
    /// What waiting for the supervised command yields.
    type Exit;

    #[doc(hidden)]
    fn mode(&self) -> Mode;

    /// The budget the supervisor gives a teardown of the tree to see every
    /// process it killed exit.
    fn reap_timeout(&self) -> Duration;

    #[doc(hidden)]
    fn finish(status: ExitStatus, report: Option<TreeReport>) -> Result<Self::Exit>;
}

/// The tree is torn down when the command exits.
#[derive(Debug, Clone, Copy)]
pub struct Foreground {
    /// The budget for a teardown to see the processes it killed exit.
    pub reap_timeout: Duration,
}

/// The tree lives as long as any descendant does.
#[derive(Debug, Clone, Copy)]
pub struct Background {
    /// The budget for a teardown to see the processes it killed exit, used
    /// when the host goes away without asking for one.
    pub reap_timeout: Duration,
}

/// How a [`Foreground`] command ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundExit {
    /// The command's own exit status, unchanged.
    pub status: ExitStatus,
    /// What the command left behind, and what was done about it.
    ///
    /// `survivors` is non-empty only when a process was still alive after the
    /// reap budget: the supervisor then exited anyway, and the process now
    /// belongs to whoever adopted it.
    pub report: TreeReport,
}

impl sealed::Sealed for Foreground {}
impl sealed::Sealed for Background {}

impl Supervision for Foreground {
    type Exit = ForegroundExit;

    fn mode(&self) -> Mode {
        Mode::Foreground
    }

    fn reap_timeout(&self) -> Duration {
        self.reap_timeout
    }

    fn finish(status: ExitStatus, report: Option<TreeReport>) -> Result<ForegroundExit> {
        // The supervisor reports in every ordinary ending of a foreground run:
        // after the command's exit, or in answer to a kill.
        let report = report.ok_or(Error::SupervisorLost)?;
        Ok(ForegroundExit { status, report })
    }
}

impl Supervision for Background {
    type Exit = ExitStatus;

    fn mode(&self) -> Mode {
        Mode::Background
    }

    fn reap_timeout(&self) -> Duration {
        self.reap_timeout
    }

    fn finish(status: ExitStatus, _report: Option<TreeReport>) -> Result<ExitStatus> {
        Ok(status)
    }
}

/// Why a tree kill did not end the tree.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TreeKillError {
    /// Processes were still alive after `SIGKILL` and the reap budget, for
    /// example one stuck in an uninterruptible kernel call; or the budget ran
    /// out before the whole tree was frozen.
    #[error("{} process(es) of the tree survived the kill", .0.survivors.len())]
    Survived(TreeReport),
    /// The supervisor failed while tearing the tree down. It killed what it had
    /// frozen first, but processes it had not reached may still run.
    #[error("the supervisor failed: {0}")]
    SupervisorFailed(String),
    /// The supervisor ended without answering, so nothing is known about the
    /// tree.
    #[error("the supervisor ended without reporting the kill")]
    SupervisorLost,
    /// The control socket failed.
    #[error("the supervisor's control socket failed: {0}")]
    Io(#[from] std::io::Error),
}

/// How the supervisor ended other than by a clean report.
#[derive(Debug)]
enum Ending {
    /// The command could not be started.
    Spawn(SpawnFailure),
    /// The command was still unreaped when the teardown budget ran out.
    Unreaped(TreeReport),
    /// The supervisor failed.
    Failed(String),
}

/// What the supervisor has said so far.
#[derive(Debug, Default)]
struct State {
    /// The latest teardown report.
    report: Option<TreeReport>,
    /// How many teardown reports have arrived.
    reports: u64,
    /// A failure the supervisor reported before its last word.
    ending: Option<Ending>,
    /// The supervisor said its last word.
    done: bool,
    /// The socket reached its end.
    closed: bool,
}

impl State {
    fn ended(&self) -> bool {
        self.done || self.closed
    }

    fn apply(&mut self, event: Event) {
        match event {
            Event::Leftover(report) | Event::Killed(report) => {
                self.report = Some(report);
                self.reports += 1;
            }
            Event::SpawnFailed(failure) => self.ending = Some(Ending::Spawn(failure)),
            Event::CommandUnreaped(report) => self.ending = Some(Ending::Unreaped(report)),
            Event::Failed(message) => self.ending = Some(Ending::Failed(message)),
            Event::Done => self.done = true,
        }
    }

    /// What a kill request amounts to once the supervisor has ended.
    fn kill_after_end(&self) -> std::result::Result<TreeReport, TreeKillError> {
        match &self.ending {
            Some(Ending::Failed(message)) => Err(TreeKillError::SupervisorFailed(message.clone())),
            Some(Ending::Unreaped(report)) => Err(TreeKillError::Survived(report.clone())),
            // Nothing was ever started, so there is no tree to kill.
            Some(Ending::Spawn(_)) => Ok(TreeReport::default()),
            None if self.done => survivors_or_empty(self.report.as_ref()),
            None => Err(TreeKillError::SupervisorLost),
        }
    }
}

/// The supervisor's messages as the reader thread has received them.
#[derive(Debug, Default)]
struct Mailbox {
    state: Mutex<State>,
    changed: Condvar,
}

impl Mailbox {
    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock leaves a consistent state: it only
        // ever gains messages.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Block until `ready` holds of the state.
    fn wait_until(&self, ready: impl Fn(&State) -> bool) -> MutexGuard<'_, State> {
        self.changed
            .wait_while(self.lock(), |state| !ready(state))
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn update(&self, change: impl FnOnce(&mut State)) {
        change(&mut self.lock());
        self.changed.notify_all();
    }
}

/// Read the supervisor's messages until its end, whoever is asking.
///
/// This runs for as long as the supervisor does, so the supervisor never
/// blocks on a full socket, however large its report. It stops at the end of
/// the stream, which comes when the supervisor exits.
fn read_events(mut from_supervisor: BufReader<UnixStream>, mailbox: &Mailbox) {
    let mut line = String::new();
    loop {
        line.clear();
        match from_supervisor.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => match serde_json::from_str::<Event>(&line) {
                Ok(event) => mailbox.update(|state| state.apply(event)),
                Err(error) => {
                    mailbox.update(|state| {
                        state.ending = Some(Ending::Failed(format!(
                            "an unreadable message from the supervisor: {error}"
                        )));
                    });
                    break;
                }
            },
            Err(error) => {
                mailbox.update(|state| {
                    state.ending = Some(Ending::Failed(format!(
                        "reading from the supervisor failed: {error}"
                    )));
                });
                break;
            }
        }
    }
    mailbox.update(|state| state.closed = true);
}

/// The host's end of the control socket, shared by everything that talks to
/// one supervisor.
#[derive(Debug)]
pub(crate) struct Shared {
    to_supervisor: UnixStream,
    mailbox: Arc<Mailbox>,
    reap_timeout: Duration,
    /// The supervisor's exit status once it has been reaped. The one place the
    /// supervisor is waited for, whoever asks first.
    exit: Mutex<Option<ExitStatus>>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        // Nobody on the host can ask for anything any more. The reader thread
        // keeps its own copy of the socket open, so closing ours would not
        // reach the supervisor; shutting down the write side does, and is what
        // makes it tear the tree down.
        let _ = self.to_supervisor.shutdown(Shutdown::Write);
    }
}

impl Shared {
    /// Start reading the supervisor's messages from `to_supervisor`.
    pub(crate) fn new(
        to_supervisor: UnixStream,
        reap_timeout: Duration,
    ) -> std::io::Result<Arc<Self>> {
        let from_supervisor = BufReader::new(to_supervisor.try_clone()?);
        let mailbox = Arc::new(Mailbox::default());
        let reader = Arc::clone(&mailbox);
        std::thread::Builder::new()
            .name("heel-supervisor-reader".into())
            .spawn(move || read_events(from_supervisor, &reader))?;
        Ok(Arc::new(Self {
            to_supervisor,
            mailbox,
            reap_timeout,
            exit: Mutex::new(None),
        }))
    }

    /// Wait for the supervisor `pid` to exit and reap it, returning its status.
    ///
    /// Every wait for a supervised process goes through here: the waiter that
    /// gets the lock first reaps, and the others receive the status it kept,
    /// so none is left with `ECHILD`. The lock is held across the wait on
    /// purpose; the only contenders are other waits for the same process.
    pub(crate) fn reap(&self, pid: u32) -> std::io::Result<ExitStatus> {
        let mut exit = self
            .exit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(status) = *exit {
            return Ok(status);
        }
        let status = reap_child(pid)?;
        *exit = Some(status);
        Ok(status)
    }

    fn send(&self, request: &Request) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(request).map_err(std::io::Error::from)?;
        line.push(b'\n');
        // A supervisor that has already exited cannot be written to; what it
        // said before leaving is in the mailbox.
        match (&self.to_supervisor).write_all(&line) {
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            other => other,
        }
    }

    /// Ask the supervisor to tear the tree down, without waiting for it.
    ///
    /// Nothing here takes a lock a waiter may be holding, so it works while
    /// another task is waiting for the command.
    pub(crate) fn request_teardown(&self) {
        if let Err(error) = self.send(&Request::Kill) {
            tracing::warn!(%error, "could not ask the supervisor to tear the tree down");
        }
    }

    fn kill(&self) -> std::result::Result<TreeReport, TreeKillError> {
        let seen = {
            let state = self.mailbox.lock();
            if state.ended() {
                // The supervisor finished by itself, which it does only when no
                // descendant is left or after a teardown that has been
                // reported.
                return state.kill_after_end();
            }
            state.reports
        };

        self.send(&Request::Kill)?;

        let state = self
            .mailbox
            .wait_until(|state| state.reports > seen || state.ended());
        match (&state.report, state.reports > seen) {
            // Either the answer to this request or, when the command ended
            // first, the supervisor's own teardown: the report this kill was
            // after.
            (Some(report), true) => survivors_or_report(report.clone()),
            _ => state.kill_after_end(),
        }
    }

    /// Wait for the supervisor's last word, returning the teardown report it
    /// made, if any.
    fn finish(&self) -> Result<Option<TreeReport>> {
        let state = self.mailbox.wait_until(|state| state.ended());
        match &state.ending {
            Some(Ending::Spawn(failure)) => Err(Error::SupervisedSpawnFailed(failure.clone())),
            Some(Ending::Unreaped(report)) => Err(Error::SupervisedCommandUnreaped(report.clone())),
            Some(Ending::Failed(message)) => Err(Error::SupervisorFailed(message.clone())),
            None if state.done => Ok(state.report.clone()),
            None => Err(Error::SupervisorLost),
        }
    }
}

/// Wait for the child `pid` and reap it.
pub(crate) fn reap_child(pid: u32) -> std::io::Result<ExitStatus> {
    let pid = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or_else(|| std::io::Error::other(format!("{pid} is not a process id")))?;
    loop {
        match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty()) {
            Ok(Some((_, status))) => return Ok(ExitStatus::from_raw(status.as_raw())),
            Ok(None) => unreachable!("a blocking wait returns a status"),
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn survivors_or_report(report: TreeReport) -> std::result::Result<TreeReport, TreeKillError> {
    if report.survivors.is_empty() {
        Ok(report)
    } else {
        Err(TreeKillError::Survived(report))
    }
}

fn survivors_or_empty(
    report: Option<&TreeReport>,
) -> std::result::Result<TreeReport, TreeKillError> {
    match report {
        Some(report) => survivors_or_report(report.clone()),
        None => Ok(TreeReport::default()),
    }
}

/// A handle that can end a supervised command's tree from anywhere.
///
/// Cloning it is cheap, so a task can wait for the command while another holds
/// this to kill it.
#[derive(Clone)]
pub struct TreeControl {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for TreeControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeControl").finish_non_exhaustive()
    }
}

impl TreeControl {
    /// Freeze, kill and reap every process of the tree.
    ///
    /// The supervisor stops the whole tree first, so nothing forks while it is
    /// being killed, and reaps each process only after killing it, so no kill
    /// can hit a reused pid. Resolves once the supervisor has reported, which
    /// it does within the supervision's reap budget plus the time to freeze.
    ///
    /// On success the report names what was killed; the supervisor then exits
    /// with the command's status, which [`SupervisedChild::wait`] returns.
    ///
    /// # Errors
    ///
    /// [`TreeKillError::Survived`] when a process outlived the kill, or the
    /// budget ran out before the tree was frozen, with the report naming what
    /// is still alive; it is never reported as success.
    pub async fn kill(&self) -> std::result::Result<TreeReport, TreeKillError> {
        let shared = Arc::clone(&self.shared);
        unblock(move || shared.kill()).await
    }
}

/// A command running under `heel supervise` inside the sandbox.
///
/// The spawned process is the supervisor, which is the command's parent; the
/// command's exit status is the supervisor's.
///
/// The tree is ended through the supervisor only: [`kill_tree`](Self::kill_tree),
/// dropping this handle, or dropping the sandbox.
///
/// Dropping this handle asks the supervisor to tear the tree down, whatever
/// [`TreeControl`] clones are still alive: this handle owns the command, and a
/// clone exists to kill it, never to keep it running. That is sound because the
/// request is idempotent (a supervisor that has already finished ignores it)
/// and nothing can wait on the command through a clone. The supervisor process
/// itself is reaped by [`wait`](Self::wait) or, if that never happens, when the
/// sandbox is dropped.
#[derive(Debug)]
pub struct SupervisedChild<M: Supervision> {
    child: Child,
    control: TreeControl,
    mode: PhantomData<M>,
}

impl<M: Supervision> Drop for SupervisedChild<M> {
    fn drop(&mut self) {
        self.control.shared.request_teardown();
    }
}

impl<M: Supervision> SupervisedChild<M> {
    pub(crate) fn new(child: Child, shared: Arc<Shared>) -> Self {
        Self {
            child,
            control: TreeControl { shared },
            mode: PhantomData,
        }
    }

    /// The supervisor's process id, which is the root of the tree.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// The command's standard input, when it was piped.
    pub fn stdin(&mut self) -> Option<&mut std::fs::File> {
        self.child.stdin()
    }

    /// The command's standard output, when it was piped.
    pub fn stdout(&mut self) -> Option<&mut std::fs::File> {
        self.child.stdout()
    }

    /// The command's standard error, when it was piped.
    pub fn stderr(&mut self) -> Option<&mut std::fs::File> {
        self.child.stderr()
    }

    /// Take ownership of the command's standard input.
    pub fn take_stdin(&mut self) -> Option<std::fs::File> {
        self.child.take_stdin()
    }

    /// Take ownership of the command's standard output.
    pub fn take_stdout(&mut self) -> Option<std::fs::File> {
        self.child.take_stdout()
    }

    /// Take ownership of the command's standard error.
    pub fn take_stderr(&mut self) -> Option<std::fs::File> {
        self.child.take_stderr()
    }

    /// A handle to kill the tree while something else waits for the command.
    pub fn tree_control(&self) -> TreeControl {
        self.control.clone()
    }

    /// Kill the whole tree. See [`TreeControl::kill`].
    ///
    /// # Errors
    ///
    /// As [`TreeControl::kill`].
    pub async fn kill_tree(&self) -> std::result::Result<TreeReport, TreeKillError> {
        self.control.kill().await
    }

    /// Wait for the supervisor, which exits once the command and everything it
    /// left behind have been dealt with.
    ///
    /// # Errors
    ///
    /// - [`Error::SupervisedSpawnFailed`] when the command could not be
    ///   started;
    /// - [`Error::SupervisedCommandUnreaped`] when the command had not exited
    ///   when the teardown budget ran out;
    /// - [`Error::SupervisorFailed`] when the supervisor failed;
    /// - [`Error::SupervisorLost`] when the supervisor ended without its last
    ///   report (it was killed from outside, so the tree may still be running).
    pub async fn wait(&mut self) -> Result<M::Exit> {
        let pid = self.child.id();
        let reaper = Arc::clone(&self.control.shared);
        let shared = Arc::clone(&self.control.shared);
        // Both at once: the supervisor's messages are read by their own
        // thread, so neither side waits on the other. The supervisor is reaped
        // through `Shared`, the same path dropping the sandbox takes, so the
        // two never compete for its status.
        let (status, report) = futures_lite::future::zip(
            unblock(move || reaper.reap(pid)),
            unblock(move || shared.finish()),
        )
        .await;
        let status = status?;
        self.child.forget_reaped();
        M::finish(status, report?)
    }

    /// The budget a teardown gets, as this command was started with.
    pub fn reap_timeout(&self) -> Duration {
        self.control.shared.reap_timeout
    }
}

/// The arguments `heel supervise` takes for a command.
pub(crate) fn arguments(
    mode: Mode,
    control: std::os::fd::RawFd,
    reap_timeout: Duration,
    program: &str,
    args: &[String],
) -> Vec<String> {
    let mut arguments = vec![
        "supervise".to_owned(),
        "--mode".to_owned(),
        mode.as_str().to_owned(),
        "--control-fd".to_owned(),
        control.to_string(),
        "--reap-timeout".to_owned(),
        reap_timeout_argument(reap_timeout),
        "--".to_owned(),
        program.to_owned(),
    ];
    arguments.extend_from_slice(args);
    arguments
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::protocol::LeftoverProcess;

    fn send_event(stream: &mut UnixStream, event: &Event) {
        let mut line = serde_json::to_vec(event).unwrap();
        line.push(b'\n');
        stream.write_all(&line).unwrap();
    }

    #[test]
    fn a_report_larger_than_the_socket_buffer_does_not_block_the_supervisor() {
        let (host, mut supervisor) = UnixStream::pair().unwrap();
        let shared = Shared::new(host, Duration::from_secs(1)).unwrap();

        let report = TreeReport {
            killed: (0..40_000)
                .map(|pid| LeftoverProcess {
                    pid,
                    name: "sleep".into(),
                })
                .collect(),
            survivors: Vec::new(),
        };
        let sent = report.clone();
        // The writer finishes only if something reads while it writes; nothing
        // on the host has asked for anything yet.
        let writer = std::thread::spawn(move || {
            send_event(&mut supervisor, &Event::Leftover(sent));
            send_event(&mut supervisor, &Event::Done);
        });
        let received = shared.finish().unwrap();
        writer.join().unwrap();

        assert_eq!(received, Some(report));
    }

    #[test]
    fn a_kill_is_answered_with_the_report_made_for_it() {
        let (host, mut supervisor) = UnixStream::pair().unwrap();
        let shared = Shared::new(host, Duration::from_secs(1)).unwrap();
        let answer = TreeReport {
            killed: vec![LeftoverProcess {
                pid: 9,
                name: "sleep".into(),
            }],
            survivors: Vec::new(),
        };
        let sent = answer.clone();
        let supervisor_side = std::thread::spawn(move || {
            let mut request = String::new();
            BufReader::new(supervisor.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            assert_eq!(request.trim(), r#""Kill""#);
            send_event(&mut supervisor, &Event::Killed(sent));
            send_event(&mut supervisor, &Event::Done);
        });

        assert_eq!(shared.kill().unwrap(), answer);
        supervisor_side.join().unwrap();
        // A later kill sees the same teardown, not an empty tree.
        assert_eq!(shared.kill().unwrap(), answer);
    }

    #[test]
    fn concurrent_waits_for_the_supervisor_all_get_its_status() {
        let (host, _supervisor) = UnixStream::pair().unwrap();
        let shared = Shared::new(host, Duration::from_secs(1)).unwrap();
        #[expect(
            clippy::zombie_processes,
            reason = "reaped by `Shared::reap`, which is what is under test"
        )]
        let child = std::process::Command::new("sh")
            .args(["-c", "exit 3"])
            .spawn()
            .unwrap();
        let pid = child.id();
        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || shared.reap(pid).unwrap())
            })
            .collect();
        for waiter in waiters {
            assert_eq!(waiter.join().unwrap().code(), Some(3));
        }
    }

    #[test]
    fn a_spawn_failure_is_a_typed_error() {
        let (host, mut supervisor) = UnixStream::pair().unwrap();
        let shared = Shared::new(host, Duration::from_secs(1)).unwrap();
        let failure = SpawnFailure {
            os_error: Some(2),
            message: "No such file or directory".into(),
        };
        send_event(&mut supervisor, &Event::SpawnFailed(failure.clone()));
        send_event(&mut supervisor, &Event::Done);

        match shared.finish() {
            Err(Error::SupervisedSpawnFailed(found)) => assert_eq!(found, failure),
            other => panic!("expected the spawn failure, got {other:?}"),
        }
    }

    #[test]
    fn a_supervisor_that_vanishes_is_lost() {
        let (host, supervisor) = UnixStream::pair().unwrap();
        let shared = Shared::new(host, Duration::from_secs(1)).unwrap();
        drop(supervisor);

        assert!(matches!(shared.finish(), Err(Error::SupervisorLost)));
        assert!(matches!(shared.kill(), Err(TreeKillError::SupervisorLost)));
    }
}
