//! The handle a caller holds on a sandboxed process.
//!
//! Unix backends spawn through `std::process::Command`, which cannot express an
//! AppContainer launch: Windows needs process and thread attributes that
//! `std::process` does not expose, so its backend carries a handle of its own.
//! [`ProcessHandle`] is what the two have in common, and [`PlatformChild`]
//! selects between them at compile time rather than behind a trait object.
//!
//! Standard streams are plain [`File`]s on both platforms. `std::process` hands
//! out its own stream types, but the Windows launcher produces pipe handles, and
//! one type for both keeps the public API from changing shape per platform.

use std::fs::File;
use std::io::{self, Read};
use std::process::{ExitStatus, Output};

use blocking::unblock;

use crate::error::Result;
use crate::sandbox::ProcessTracker;

/// A live handle to one spawned process.
pub(crate) trait ProcessHandle: Send + std::fmt::Debug + 'static {
    /// The process identifier.
    fn id(&self) -> u32;

    /// Block until the process exits.
    fn wait(&mut self) -> io::Result<ExitStatus>;

    /// Report the exit status if the process has already exited.
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;

    /// Kill the process and every process it spawned, then reap it.
    ///
    /// Killing an already-exited process succeeds: the caller wants it gone,
    /// and it is.
    fn kill(&mut self) -> io::Result<()>;

    /// The pipe connected to the process's standard input, if it has one.
    fn stdin(&mut self) -> &mut Option<File>;

    /// The pipe connected to the process's standard output, if it has one.
    fn stdout(&mut self) -> &mut Option<File>;

    /// The pipe connected to the process's standard error, if it has one.
    fn stderr(&mut self) -> &mut Option<File>;
}

/// The process handle this platform's backend produces.
#[cfg(unix)]
pub(crate) type PlatformChild = unix::UnixChild;

/// The process handle this platform's backend produces.
#[cfg(windows)]
pub(crate) type PlatformChild = crate::platform::windows::AppContainerChild;

/// A spawned child process in the sandbox.
#[derive(Debug)]
pub struct Child {
    inner: Option<PlatformChild>,
    tracker: Option<ProcessTracker>,
    pid: u32,
}

/// The error reported once a child has been waited on and its handle released.
fn consumed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "child process has already been consumed",
    )
}

impl Child {
    /// Wrap a freshly spawned process.
    pub(crate) fn new(inner: PlatformChild) -> Self {
        let pid = inner.id();
        Self {
            inner: Some(inner),
            tracker: None,
            pid,
        }
    }

    /// Register the child with the sandbox, so that dropping it kills the child.
    pub(crate) fn with_tracker(mut self, tracker: ProcessTracker) -> Self {
        self.tracker = Some(tracker);
        self
    }

    /// The handle, which is present until the child has been consumed.
    fn handle(&mut self) -> Result<&mut PlatformChild> {
        Ok(self.inner.as_mut().ok_or_else(consumed)?)
    }

    fn unregister(&mut self) {
        if let Some(tracker) = self.tracker.take() {
            tracker.unregister(self.pid);
        }
    }

    /// Access the child's standard input.
    pub fn stdin(&mut self) -> Option<&mut File> {
        self.inner.as_mut().and_then(|c| c.stdin().as_mut())
    }

    /// Access the child's standard output.
    pub fn stdout(&mut self) -> Option<&mut File> {
        self.inner.as_mut().and_then(|c| c.stdout().as_mut())
    }

    /// Access the child's standard error.
    pub fn stderr(&mut self) -> Option<&mut File> {
        self.inner.as_mut().and_then(|c| c.stderr().as_mut())
    }

    /// Take ownership of the child's standard input.
    pub fn take_stdin(&mut self) -> Option<File> {
        self.inner.as_mut().and_then(|c| c.stdin().take())
    }

    /// Take ownership of the child's standard output.
    pub fn take_stdout(&mut self) -> Option<File> {
        self.inner.as_mut().and_then(|c| c.stdout().take())
    }

    /// Take ownership of the child's standard error.
    pub fn take_stderr(&mut self) -> Option<File> {
        self.inner.as_mut().and_then(|c| c.stderr().take())
    }

    /// The process ID.
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Wait for the child to exit.
    ///
    /// # Errors
    ///
    /// Returns an error if the child has already been consumed, or if waiting
    /// fails.
    pub async fn wait(&mut self) -> Result<ExitStatus> {
        let mut inner = self.inner.take().ok_or_else(consumed)?;
        let (inner, status) = unblock(move || {
            let status = inner.wait();
            (inner, status)
        })
        .await;
        self.inner = Some(inner);
        let status = status?;
        self.unregister();
        Ok(status)
    }

    /// Wait for the child to exit and collect everything it wrote.
    ///
    /// The output pipes are drained on threads of their own while the process
    /// runs. Waiting first would deadlock as soon as a child writes more than a
    /// pipe buffer holds, because nothing would be reading the other end.
    ///
    /// # Errors
    ///
    /// Returns an error if the child has already been consumed, or if waiting
    /// or reading fails.
    pub async fn wait_with_output(mut self) -> Result<Output> {
        let mut inner = self.inner.take().ok_or_else(consumed)?;

        // Closing standard input releases a child that is blocked reading it.
        drop(inner.stdin().take());
        let stdout = inner.stdout().take();
        let stderr = inner.stderr().take();

        let output = unblock(move || -> io::Result<Output> {
            let (status, stdout, stderr) = std::thread::scope(|scope| {
                let out = scope.spawn(move || drain(stdout));
                let err = scope.spawn(move || drain(stderr));
                let status = inner.wait();
                (status, out.join(), err.join())
            });

            Ok(Output {
                status: status?,
                stdout: joined(stdout)?,
                stderr: joined(stderr)?,
            })
        })
        .await?;

        self.unregister();
        Ok(output)
    }

    /// Kill the child and everything it spawned, then reap it.
    ///
    /// # Errors
    ///
    /// Returns an error if the child has already been consumed, or if killing
    /// fails for a reason other than the process already being gone.
    pub fn kill(&mut self) -> Result<()> {
        self.handle()?.kill()?;
        self.unregister();
        Ok(())
    }

    /// Check whether the child has exited, without blocking.
    ///
    /// # Errors
    ///
    /// Returns an error if the child has already been consumed, or if the check
    /// fails.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        let status = self.handle()?.try_wait()?;
        if status.is_some() {
            self.unregister();
        }
        Ok(status)
    }
}

/// Unwrap a reader thread's result, turning a panic into an error.
///
/// Draining a pipe does not panic, so this is about not swallowing it if it
/// ever does.
fn joined(result: std::thread::Result<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    result.unwrap_or_else(|_| Err(io::Error::other("an output reader panicked")))
}

/// Read a pipe to end of file, or return nothing when there is no pipe.
fn drain(pipe: Option<File>) -> io::Result<Vec<u8>> {
    let Some(mut pipe) = pipe else {
        return Ok(Vec::new());
    };
    let mut buffer = Vec::new();
    pipe.read_to_end(&mut buffer)?;
    Ok(buffer)
}

#[cfg(unix)]
pub(crate) mod unix {
    //! The process handle for backends that spawn through `std::process`.

    use std::os::fd::OwnedFd;

    use super::{ExitStatus, File, ProcessHandle, io};

    /// A child spawned by `std::process::Command`.
    #[derive(Debug)]
    pub(crate) struct UnixChild {
        inner: std::process::Child,
        stdin: Option<File>,
        stdout: Option<File>,
        stderr: Option<File>,
    }

    impl UnixChild {
        /// Adopt a freshly spawned process.
        pub(crate) fn new(mut inner: std::process::Child) -> Self {
            // The stream types are pipes; converting once here is what lets the
            // public API be the same on every platform.
            let stdin = inner
                .stdin
                .take()
                .map(|pipe| File::from(OwnedFd::from(pipe)));
            let stdout = inner
                .stdout
                .take()
                .map(|pipe| File::from(OwnedFd::from(pipe)));
            let stderr = inner
                .stderr
                .take()
                .map(|pipe| File::from(OwnedFd::from(pipe)));
            Self {
                inner,
                stdin,
                stdout,
                stderr,
            }
        }
    }

    impl ProcessHandle for UnixChild {
        fn id(&self) -> u32 {
            self.inner.id()
        }

        fn wait(&mut self) -> io::Result<ExitStatus> {
            self.inner.wait()
        }

        fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            self.inner.try_wait()
        }

        fn kill(&mut self) -> io::Result<()> {
            // SAFETY: a negative PID targets the process group created at
            // spawn, which is this child and its descendants.
            let result = unsafe { libc::kill(-(self.inner.id() as i32), libc::SIGKILL) };
            if result != 0 {
                let error = io::Error::last_os_error();
                // ESRCH means the group is already gone, which is success here.
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }

            // Reap, so the kernel releases the entry rather than leaving a
            // zombie.
            self.inner.wait()?;
            Ok(())
        }

        fn stdin(&mut self) -> &mut Option<File> {
            &mut self.stdin
        }

        fn stdout(&mut self) -> &mut Option<File> {
            &mut self.stdout
        }

        fn stderr(&mut self) -> &mut Option<File> {
            &mut self.stderr
        }
    }
}
