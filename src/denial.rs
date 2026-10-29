//! Reports of the accesses a sandbox denied.
//!
//! On macOS the kernel decides every denial and reports it only to the system
//! log, as a process name and an operation with nothing that names the profile.
//! The profile therefore tags each of its denials with a message unique to the
//! sandbox, and [`DenialRecorder`] follows the system log for that tag. On Linux
//! the broker that judges the host protection policies records its own refusals.
//!
//! Recording is a property of the platform, not of the sandbox: a platform whose
//! kernel reports denials nowhere, or nowhere a process can follow, answers
//! [`Sandbox::record_denials`](crate::Sandbox::record_denials) with
//! [`Error::UnsupportedPolicy`](crate::Error::UnsupportedPolicy) instead of an
//! empty list that would read as "nothing was denied".

#[cfg(target_os = "macos")]
use std::path::Path;

use serde::Serialize;

#[cfg(not(target_os = "macos"))]
use crate::error::Result;

/// The message every denial of one sandbox carries.
///
/// The system log reports a denial as the process and the operation, with
/// nothing that names the profile, so the tag is how the denials of this
/// sandbox are told apart from those of every other sandboxed process on the
/// machine.
#[cfg(target_os = "macos")]
pub(crate) fn denial_tag(working_dir: &Path) -> String {
    let name = working_dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("heel:{name}")
}

/// One access the sandbox refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Denial {
    /// When the kernel reported it, in the system log's local time.
    pub timestamp: String,
    /// The name of the process that was refused.
    pub process: String,
    /// The process id.
    pub pid: u32,
    /// The refused operation, such as `file-read-data` or `mach-lookup`.
    pub operation: String,
    /// What the operation was aimed at: a path, a service name, or empty when
    /// the operation has no target.
    pub target: String,
    /// How many identical refusals the report stands for. The kernel folds
    /// repeats into one report.
    pub repeats: u32,
}

impl Denial {
    /// Read one system log message, `None` for a message that is not a denial
    /// report of the sandbox tagged `tag`.
    ///
    /// A report reads `Sandbox: cat(27314) deny(1) file-read-data /path`, with
    /// the profile's message on the line after it, and a run of repeats reads
    /// `16 duplicate reports for Sandbox: ...`.
    #[cfg(target_os = "macos")]
    pub(crate) fn parse(timestamp: &str, message: &str, tag: &str) -> Option<Self> {
        let mut lines = message.lines();
        let report = lines.next()?;
        if !lines.any(|line| line == tag) {
            return None;
        }

        let (repeats, report) = match report.split_once(" duplicate report") {
            Some((count, rest)) => {
                let (_, report) = rest.split_once("for Sandbox: ")?;
                (count.trim().parse().ok()?, report)
            }
            None => (1, report.strip_prefix("Sandbox: ")?),
        };

        let (subject, action) = report.split_once(" deny(")?;
        let (process, pid) = subject.strip_suffix(')')?.rsplit_once('(')?;
        let (_, action) = action.split_once(") ")?;
        let (operation, target) = action.split_once(' ').unwrap_or((action, ""));

        Some(Self {
            timestamp: timestamp.to_owned(),
            process: process.to_owned(),
            pid: pid.parse().ok()?,
            operation: operation.to_owned(),
            target: target.to_owned(),
            repeats,
        })
    }
}

#[cfg(target_os = "macos")]
pub use recorder::DenialRecorder;

/// Collects the denials the broker of one sandbox records.
///
/// Landlock reports its denials to the audit log, which an unprivileged process
/// cannot read, so the broker records the refusals of the host protection
/// policies itself.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct DenialRecorder {
    sink: std::sync::Arc<crate::platform::linux::broker::sink::DenialSink>,
    subscriber: crate::platform::linux::broker::sink::Subscriber,
}

#[cfg(target_os = "linux")]
impl DenialRecorder {
    pub(crate) fn start(
        sink: &std::sync::Arc<crate::platform::linux::broker::sink::DenialSink>,
    ) -> Self {
        Self {
            subscriber: sink.subscribe(),
            sink: std::sync::Arc::clone(sink),
        }
    }

    /// Stop collecting and return the denials recorded since the recorder
    /// started, with repeats of one operation on one target folded together.
    pub async fn finish(self) -> Result<Vec<Denial>> {
        let mut folded: Vec<Denial> = Vec::new();
        for denial in self.sink.finish(&self.subscriber) {
            match folded.iter_mut().find(|seen| {
                seen.pid == denial.pid
                    && seen.operation == denial.operation
                    && seen.target == denial.target
            }) {
                Some(seen) => seen.repeats += denial.repeats,
                None => folded.push(denial),
            }
        }
        Ok(folded)
    }
}

/// Follows the system log for the denials of one sandbox.
///
/// Here no denials can be recorded, so a recorder cannot be started and this
/// type is never constructed.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[derive(Debug)]
pub struct DenialRecorder(std::convert::Infallible);

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl DenialRecorder {
    pub(crate) async fn start() -> Result<Self> {
        Err(crate::error::Error::UnsupportedPolicy {
            policy: "denial reports",
            platform: std::env::consts::OS,
        })
    }

    /// Stop following and return the denials reported.
    pub async fn finish(self) -> Result<Vec<Denial>> {
        match self.0 {}
    }
}

#[cfg(target_os = "macos")]
mod recorder {
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use blocking::unblock;

    use super::Denial;
    use crate::error::{Error, Result};

    /// The system log viewer, resolved absolutely like the sandbox launcher.
    const LOG: &str = "/usr/bin/log";

    /// The system sandbox launcher, used to provoke the readiness denial.
    const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

    /// How long the follower is given to start delivering before recording is
    /// declared failed.
    const READY_TIMEOUT: Duration = Duration::from_secs(15);

    /// How long the follower is given to deliver the readiness denial before the
    /// next one is provoked.
    const PROBE_INTERVAL: Duration = Duration::from_millis(250);

    /// How long the system log is given to deliver the last reports once the
    /// sandboxed work is over. Reports reach a follower within a fraction of a
    /// second of the denial.
    const DRAIN: Duration = Duration::from_millis(500);

    /// Follows the system log for the denials of one sandbox.
    ///
    /// Start it before the work whose denials are wanted, then call
    /// [`DenialRecorder::finish`] once that work is over. Denials made before
    /// it started are not reported.
    #[derive(Debug)]
    pub struct DenialRecorder {
        follower: Child,
        reader: Option<std::thread::JoinHandle<()>>,
        denials: Arc<Mutex<Vec<Denial>>>,
    }

    impl DenialRecorder {
        /// Start following the denials tagged `tag`, returning once the system
        /// log is delivering them.
        ///
        /// The follower announces itself before it is subscribed, so readiness
        /// is established by provoking a denial under a tag of our own
        /// (`<tag>:ready`) until the follower reports it.
        pub(crate) async fn start(tag: String) -> Result<Self> {
            unblock(move || {
                let predicate =
                    format!("sender == \"Sandbox\" AND eventMessage CONTAINS \"{tag}\"");
                let mut follower = Command::new(LOG)
                    .args(["stream", "--style", "ndjson", "--predicate", &predicate])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|error| {
                        Error::InitFailed(format!("cannot start {LOG} to follow denials: {error}"))
                    })?;
                let stdout = follower.stdout.take().ok_or_else(|| {
                    Error::InitFailed("the denial follower has no standard output".into())
                })?;

                let denials = Arc::new(Mutex::new(Vec::new()));
                let (ready_sender, ready) = std::sync::mpsc::channel();
                let sink = Arc::clone(&denials);
                let ready_tag = format!("{tag}:ready");
                let probe = format!("(version 1)(deny default (with message \"{ready_tag}\"))");
                let reader = std::thread::Builder::new()
                    .name("heel-denials".into())
                    .spawn(move || {
                        for line in BufReader::new(stdout)
                            .lines()
                            .map_while(std::result::Result::ok)
                        {
                            let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) else {
                                continue;
                            };
                            let (Some(timestamp), Some(message)) =
                                (event["timestamp"].as_str(), event["eventMessage"].as_str())
                            else {
                                continue;
                            };
                            if message.lines().any(|line| line == ready_tag) {
                                let _ = ready_sender.send(());
                            } else if let Some(denial) = Denial::parse(timestamp, message, &tag) {
                                sink.lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .push(denial);
                            }
                        }
                    })
                    .map_err(Error::Io)?;

                // Owned from here, so the follower is stopped on the failure path.
                let recorder = Self {
                    follower,
                    reader: Some(reader),
                    denials,
                };
                let deadline = std::time::Instant::now() + READY_TIMEOUT;
                while ready.recv_timeout(PROBE_INTERVAL).is_err() {
                    if std::time::Instant::now() >= deadline {
                        return Err(Error::InitFailed(
                            "the denial follower did not start delivering in time".into(),
                        ));
                    }
                    // The probe's own failure to exec is the denial it provokes.
                    let _ = Command::new(SANDBOX_EXEC)
                        .args(["-p", &probe, "/usr/bin/true"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                Ok(recorder)
            })
            .await
        }

        /// Stop following and return every denial reported since the recorder
        /// started.
        pub async fn finish(mut self) -> Result<Vec<Denial>> {
            unblock(move || {
                std::thread::sleep(DRAIN);
                self.stop();
                let denials = std::mem::take(
                    &mut *self
                        .denials
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
                Ok(denials)
            })
            .await
        }

        /// Kill the follower this recorder started, and wait for its reader.
        fn stop(&mut self) {
            let _ = self.follower.kill();
            let _ = self.follower.wait();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    impl Drop for DenialRecorder {
        fn drop(&mut self) {
            self.stop();
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    const TAG: &str = "heel:test";

    #[test]
    fn a_tagged_report_is_parsed() {
        let denial = Denial::parse(
            "t",
            "Sandbox: cat(27314) deny(1) file-read-data /Users/x/.ssh/id_rsa\nheel:test",
            TAG,
        )
        .unwrap();
        assert_eq!(denial.process, "cat");
        assert_eq!(denial.pid, 27314);
        assert_eq!(denial.operation, "file-read-data");
        assert_eq!(denial.target, "/Users/x/.ssh/id_rsa");
        assert_eq!(denial.repeats, 1);
    }

    #[test]
    fn a_target_with_spaces_is_kept_whole() {
        let denial = Denial::parse(
            "t",
            "Sandbox: cat(1) deny(1) file-read-data /Users/x/Library/Application Support/Arc\nheel:test",
            TAG,
        )
        .unwrap();
        assert_eq!(denial.target, "/Users/x/Library/Application Support/Arc");
    }

    #[test]
    fn an_operation_without_a_target_has_an_empty_one() {
        let denial =
            Denial::parse("t", "Sandbox: sh(5) deny(1) process-fork\nheel:test", TAG).unwrap();
        assert_eq!(denial.operation, "process-fork");
        assert_eq!(denial.target, "");
    }

    #[test]
    fn a_process_name_with_parentheses_is_kept_whole() {
        let denial = Denial::parse(
            "t",
            "Sandbox: Helper (Renderer)(77) deny(1) mach-lookup com.apple.SecurityServer\nheel:test",
            TAG,
        )
        .unwrap();
        assert_eq!(denial.process, "Helper (Renderer)");
        assert_eq!(denial.pid, 77);
        assert_eq!(denial.target, "com.apple.SecurityServer");
    }

    #[test]
    fn folded_repeats_carry_their_count() {
        let denial = Denial::parse(
            "t",
            "16 duplicate reports for Sandbox: cat(9) deny(1) file-read-data /x\nheel:test",
            TAG,
        )
        .unwrap();
        assert_eq!(denial.repeats, 16);
        assert_eq!(denial.target, "/x");
    }

    #[test]
    fn another_sandboxes_report_is_not_ours() {
        assert!(
            Denial::parse(
                "t",
                "Sandbox: cat(1) deny(1) file-read-data /x\nheel:other",
                TAG
            )
            .is_none()
        );
        assert!(Denial::parse("t", "Sandbox: cat(1) deny(1) file-read-data /x", TAG).is_none());
    }
}
