//! The host's side of a supervised command.

use std::io::{BufRead, BufReader, Write};
use std::marker::PhantomData;
use std::os::unix::net::UnixStream;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use blocking::unblock;

use crate::error::{Error, Result};
use crate::platform::Child;

use super::protocol::{Event, Mode, Request, TreeReport, reap_timeout_argument};

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
    /// example one stuck in an uninterruptible kernel call.
    #[error("{} process(es) of the tree survived SIGKILL", .0.survivors.len())]
    Survived(TreeReport),
    /// The supervisor ended without answering, so nothing is known about the
    /// tree.
    #[error("the supervisor ended without reporting the kill")]
    SupervisorLost,
    /// The control socket failed.
    #[error("the supervisor's control socket failed: {0}")]
    Io(#[from] std::io::Error),
}

/// What the supervisor has said so far.
struct Inbox {
    from_supervisor: BufReader<UnixStream>,
    /// The latest teardown report.
    report: Option<TreeReport>,
    /// The supervisor said its last word.
    done: bool,
    /// The socket reached its end.
    closed: bool,
}

impl Inbox {
    /// Take in one message, returning it.
    fn next(&mut self) -> std::io::Result<Option<Event>> {
        let mut line = String::new();
        if self.from_supervisor.read_line(&mut line)? == 0 {
            self.closed = true;
            return Ok(None);
        }
        let event: Event = serde_json::from_str(&line)?;
        match &event {
            Event::Leftover(report) | Event::Killed(report) => {
                self.report = Some(report.clone());
            }
            Event::Done => self.done = true,
        }
        Ok(Some(event))
    }
}

struct Shared {
    to_supervisor: UnixStream,
    inbox: Mutex<Inbox>,
    reap_timeout: Duration,
}

impl Shared {
    fn inbox(&self) -> MutexGuard<'_, Inbox> {
        // A panic while reading leaves a consistent inbox: it only ever gains
        // messages.
        self.inbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn kill(&self) -> std::result::Result<TreeReport, TreeKillError> {
        let mut inbox = self.inbox();
        if inbox.done {
            // The supervisor finished by itself, which it does only when no
            // descendant is left or after a teardown that has been reported.
            return survivors_or_empty(inbox.report.as_ref());
        }
        if inbox.closed {
            return Err(TreeKillError::SupervisorLost);
        }

        let mut request = serde_json::to_vec(&Request::Kill).map_err(std::io::Error::from)?;
        request.push(b'\n');
        // A supervisor that has already exited cannot be written to; what it
        // said before leaving is read below.
        match (&self.to_supervisor).write_all(&request) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(error) => return Err(error.into()),
        }

        match inbox.next()? {
            Some(Event::Killed(report)) => survivors_or_report(report),
            // The command ended first and the supervisor tore the tree down on
            // its own: that is the report this kill was after.
            Some(Event::Leftover(report)) => survivors_or_report(report),
            Some(Event::Done) => survivors_or_empty(inbox.report.as_ref()),
            None => Err(TreeKillError::SupervisorLost),
        }
    }

    /// Read everything the supervisor says until its last word.
    fn finish(&self) -> Result<Option<TreeReport>> {
        let mut inbox = self.inbox();
        while !inbox.done {
            if inbox.next()?.is_none() {
                return Err(Error::SupervisorLost);
            }
        }
        Ok(inbox.report.take())
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
    /// [`TreeKillError::Survived`] when a process outlived the kill, with the
    /// report naming it; it is never reported as success.
    pub async fn kill(&self) -> std::result::Result<TreeReport, TreeKillError> {
        let shared = Arc::clone(&self.shared);
        unblock(move || shared.kill()).await
    }
}

/// A command running under `heel supervise` inside the sandbox.
///
/// The spawned process is the supervisor, which is the command's parent; the
/// command's exit status is the supervisor's.
#[derive(Debug)]
pub struct SupervisedChild<M: Supervision> {
    child: Child,
    control: TreeControl,
    mode: PhantomData<M>,
}

impl<M: Supervision> SupervisedChild<M> {
    pub(crate) fn new(
        child: Child,
        to_supervisor: UnixStream,
        reap_timeout: Duration,
    ) -> Result<Self> {
        let from_supervisor = BufReader::new(to_supervisor.try_clone()?);
        Ok(Self {
            child,
            control: TreeControl {
                shared: Arc::new(Shared {
                    to_supervisor,
                    inbox: Mutex::new(Inbox {
                        from_supervisor,
                        report: None,
                        done: false,
                        closed: false,
                    }),
                    reap_timeout,
                }),
            },
            mode: PhantomData,
        })
    }

    /// The supervisor's process id, which is the root of the tree.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// The process handle, for the command's standard streams.
    ///
    /// Its `kill` signals the supervisor's process group only; use
    /// [`kill_tree`](Self::kill_tree) to end the whole tree.
    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
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
    /// [`Error::SupervisorLost`] when the supervisor ended without its last
    /// report (it was killed from outside, so the tree may still be running).
    pub async fn wait(&mut self) -> Result<M::Exit> {
        let status = self.child.wait().await?;
        let shared = Arc::clone(&self.control.shared);
        let report = unblock(move || shared.finish()).await?;
        M::finish(status, report)
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
