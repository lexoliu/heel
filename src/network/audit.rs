//! Audit log for sandboxed network access.
//!
//! Every policy decision — allowed or denied — is appended as one JSON line,
//! independent of which [`NetworkPolicy`] is in force. Wrap any policy in
//! [`Audited`] to record its verdicts. The sink is either a daily-rotated set
//! of files ([`NetworkAuditLog::rolling_daily`]) for a long-lived host, or one
//! file ([`NetworkAuditLog::file`]) for a harness that wants the decisions of
//! exactly one run.
//!
//! The log is write-ahead: a decision is on disk before the connection it
//! concerns is opened or refused, so anyone who observes the connection's
//! outcome also observes its record.

use std::io::{self, Write};
use std::path::Path;
use std::time::SystemTime;

use async_channel::{Receiver, Sender, bounded, unbounded};
use serde::Serialize;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

use crate::error::{Error, Result};
use crate::network::{DomainRequest, NetworkPolicy};

/// One audited network access decision, serialized as a JSON line.
#[derive(Debug, Serialize)]
struct NetworkAuditRecord<'a> {
    /// RFC 3339 timestamp of the decision, with millisecond resolution so that
    /// decisions stay ordered within a single second.
    timestamp: String,
    /// Domain or IP the sandboxed process tried to reach.
    host: &'a str,
    /// Destination port.
    port: u16,
    /// Whether the active policy allowed the connection.
    allowed: bool,
}

/// One line handed to the writer thread, with the channel its outcome is
/// reported on.
struct PendingLine {
    line: Vec<u8>,
    written: Sender<io::Result<()>>,
}

/// JSONL sink for network access decisions.
///
/// Lines are written by one dedicated thread that owns the sink, in the order
/// the decisions were made; [`NetworkAuditLog::record`] resolves once its line
/// has been written and flushed. Cloning shares the thread, which exits when
/// the last clone is dropped.
#[derive(Clone)]
pub struct NetworkAuditLog {
    lines: Sender<PendingLine>,
}

impl std::fmt::Debug for NetworkAuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkAuditLog").finish_non_exhaustive()
    }
}

impl NetworkAuditLog {
    /// File name prefix for rotated audit log files.
    pub const FILE_PREFIX: &'static str = "network-audit";

    /// Open a daily-rotated audit log under `directory`, keeping at most
    /// `max_files` rotated files.
    pub fn rolling_daily(directory: impl AsRef<Path>, max_files: usize) -> Result<Self> {
        let appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix(Self::FILE_PREFIX)
            .filename_suffix("jsonl")
            .max_log_files(max_files)
            .build(directory.as_ref())
            .map_err(|error| Error::AuditLog(error.to_string()))?;
        Self::with_sink(appender)
    }

    /// Append every decision to the single file at `path`, creating it if it
    /// does not exist and keeping whatever it already holds.
    ///
    /// One file per run is what a harness that starts many sandboxes wants: the
    /// decisions of exactly that sandbox, with nothing to split apart
    /// afterwards. The parent directory must already exist — creating it here
    /// would silently produce an audit trail somewhere the caller did not mean.
    pub fn file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        // A bare file name has an empty parent, which names the current
        // directory rather than a missing one.
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        if !parent.is_dir() {
            return Err(Error::AuditLog(format!(
                "audit log directory {} does not exist",
                parent.display()
            )));
        }

        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|error| Error::AuditLog(format!("cannot open {}: {error}", path.display())))?;
        Self::with_sink(file)
    }

    /// Hand `sink` to the writer thread every clone of this log writes through.
    fn with_sink(mut sink: impl Write + Send + 'static) -> Result<Self> {
        let (lines, pending): (Sender<PendingLine>, Receiver<PendingLine>) = unbounded();
        std::thread::Builder::new()
            .name("heel-network-audit".into())
            .spawn(move || {
                // `recv_blocking` fails only once every sender is gone, which is
                // when the last clone of the log has been dropped.
                while let Ok(PendingLine { line, written }) = pending.recv_blocking() {
                    let result = sink.write_all(&line).and_then(|()| sink.flush());
                    // The recorder may have given up waiting; its line is on
                    // disk either way.
                    let _ = written.send_blocking(result);
                }
            })
            .map_err(|error| Error::AuditLog(format!("cannot start the writer thread: {error}")))?;
        Ok(Self { lines })
    }

    /// Record one policy decision, resolving once the line is on disk.
    ///
    /// Fails when the line could not be written; the caller decides what a
    /// decision without a record means ([`Audited`] refuses the connection).
    pub async fn record(&self, request: &DomainRequest, allowed: bool) -> Result<()> {
        let record = NetworkAuditRecord {
            timestamp: humantime::format_rfc3339_millis(SystemTime::now()).to_string(),
            host: request.host(),
            port: request.port(),
            allowed,
        };
        let mut line = serde_json::to_vec(&record)
            .map_err(|error| Error::AuditLog(format!("cannot serialize record: {error}")))?;
        line.push(b'\n');
        let (written, outcome) = bounded(1);
        self.lines
            .send(PendingLine { line, written })
            .await
            .map_err(|_| Error::AuditLog("writer thread is gone".into()))?;
        match outcome.recv().await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(Error::AuditLog(format!("cannot write record: {error}"))),
            Err(_) => Err(Error::AuditLog(
                "writer thread exited before writing".into(),
            )),
        }
    }
}

/// Policy decorator that records every verdict of the inner policy.
#[derive(Clone, Debug)]
pub struct Audited<N> {
    inner: N,
    log: NetworkAuditLog,
}

impl<N> Audited<N> {
    /// Audit every decision of `inner` into `log`.
    pub fn new(inner: N, log: NetworkAuditLog) -> Self {
        Self { inner, log }
    }
}

impl<N: NetworkPolicy> NetworkPolicy for Audited<N> {
    /// Auditing does not change what the inner policy permits, so a wrapped
    /// [`DenyAll`](crate::DenyAll) still skips the proxy entirely.
    const DENIES_ALL: bool = N::DENIES_ALL;

    /// A decision that could not be recorded is answered as a refusal: an
    /// audited sandbox never opens a connection the log does not show.
    async fn check(&self, request: &DomainRequest) -> bool {
        let allowed = self.inner.check(request).await;
        match self.log.record(request, allowed).await {
            Ok(()) => allowed,
            Err(error) => {
                tracing::error!(%error, host = %request.host(), port = request.port(), "network audit: refusing an unrecorded decision");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{AllowAll, DenyAll};

    fn read_audit_lines(dir: &Path) -> Vec<serde_json::Value> {
        let mut lines = Vec::new();
        for entry in std::fs::read_dir(dir).expect("audit dir must exist") {
            let path = entry.expect("dir entry").path();
            let content = std::fs::read_to_string(&path).expect("audit file readable");
            for line in content.lines() {
                lines.push(serde_json::from_str(line).expect("audit line is JSON"));
            }
        }
        lines
    }

    #[test]
    fn audited_policy_records_allow_and_deny() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = NetworkAuditLog::rolling_daily(dir.path(), 3).expect("audit log opens");

        smol::block_on(async {
            let allow = Audited::new(AllowAll, log.clone());
            let deny = Audited::new(DenyAll, log.clone());
            let request = DomainRequest::new("api.github.com", 443);
            assert!(allow.check(&request).await);
            assert!(!deny.check(&request).await);
        });

        let lines = read_audit_lines(dir.path());
        assert_eq!(lines.len(), 2, "expected two audit records: {lines:?}");
        assert!(
            lines
                .iter()
                .all(|line| line["host"] == "api.github.com" && line["port"] == 443)
        );
        assert!(lines.iter().any(|line| line["allowed"] == true));
        assert!(lines.iter().any(|line| line["allowed"] == false));
    }

    #[test]
    fn a_file_log_writes_one_line_per_decision() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("run.jsonl");
        let log = NetworkAuditLog::file(&path).expect("audit log opens");

        smol::block_on(async {
            let policy = Audited::new(AllowAll, log.clone());
            for port in [80, 443, 8080] {
                assert!(policy.check(&DomainRequest::new("example.com", port)).await);
            }
        });

        let content = std::fs::read_to_string(&path).expect("audit file readable");
        let lines: Vec<serde_json::Value> = content
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
            .collect();

        assert_eq!(lines.len(), 3, "expected one line per decision: {lines:?}");
        assert!(lines.iter().all(|line| line["allowed"] == true));
        let ports: Vec<_> = lines.iter().map(|line| line["port"].clone()).collect();
        assert_eq!(ports, [80, 443, 8080]);
    }

    #[test]
    fn a_file_log_appends_to_what_is_already_there() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("run.jsonl");

        for _ in 0..2 {
            let log = NetworkAuditLog::file(&path).expect("audit log opens");
            smol::block_on(log.record(&DomainRequest::new("example.com", 443), true))
                .expect("record written");
        }

        let content = std::fs::read_to_string(&path).expect("audit file readable");
        assert_eq!(content.lines().count(), 2, "reopening must not truncate");
    }

    #[test]
    fn a_missing_parent_directory_is_an_error_rather_than_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent").join("run.jsonl");

        let error = NetworkAuditLog::file(&path).expect_err("must fail");
        assert!(matches!(error, Error::AuditLog(_)), "got {error:?}");
        assert!(!dir.path().join("absent").exists());
    }

    /// A sink that reports when a write has reached it and then waits for the
    /// test to open a gate, so the test can observe a recorder that is still
    /// pending while its line is not yet written.
    struct GatedSink {
        entered: std::sync::mpsc::Sender<()>,
        gate: std::sync::mpsc::Receiver<()>,
        written: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl Write for GatedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.entered.send(()).expect("the test listens");
            self.gate.recv().expect("the test opens the gate");
            self.written
                .lock()
                .expect("sink lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_record_resolves_only_once_its_line_is_written() {
        let (entered, write_started) = std::sync::mpsc::channel();
        let (open_gate, gate) = std::sync::mpsc::channel();
        let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = NetworkAuditLog::with_sink(GatedSink {
            entered,
            gate,
            written: std::sync::Arc::clone(&written),
        })
        .expect("audit log opens");

        let mut recording = smol::spawn({
            let log = log.clone();
            async move {
                log.record(&DomainRequest::new("api.github.com", 443), true)
                    .await
            }
        });
        // The writer thread now holds the line and is blocked on the gate.
        write_started.recv().expect("the write started");
        assert!(
            smol::block_on(futures_lite::future::poll_once(&mut recording)).is_none(),
            "record resolved before its line was written"
        );
        assert!(written.lock().expect("sink lock").is_empty());

        open_gate.send(()).expect("open the gate");
        smol::block_on(recording).expect("record written");
        let content =
            String::from_utf8(written.lock().expect("sink lock").clone()).expect("utf8 line");
        assert!(content.contains("api.github.com"), "{content}");
    }

    /// A sink that refuses every write.
    struct BrokenSink;

    impl Write for BrokenSink {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk gone"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_unrecorded_decision_is_a_refusal() {
        let log = NetworkAuditLog::with_sink(BrokenSink).expect("audit log opens");
        smol::block_on(async {
            let policy = Audited::new(AllowAll, log.clone());
            let request = DomainRequest::new("api.github.com", 443);
            assert!(!policy.check(&request).await, "allowed without a record");
            assert!(matches!(
                log.record(&request, true).await,
                Err(Error::AuditLog(message)) if message.contains("disk gone")
            ));
        });
    }

    // Checked at compile time: the marker decides whether a proxy runs at all,
    // so it must be a property of the type rather than of a test run.
    const _: () = assert!(Audited::<DenyAll>::DENIES_ALL);
    const _: () = assert!(!Audited::<AllowAll>::DENIES_ALL);
}
