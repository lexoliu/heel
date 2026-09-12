//! Audit log for sandboxed network access.
//!
//! Every policy decision — allowed or denied — is appended as one JSON line,
//! independent of which [`NetworkPolicy`] is in force. Wrap any policy in
//! [`Audited`] to record its verdicts. The sink is either a daily-rotated set
//! of files ([`NetworkAuditLog::rolling_daily`]) for a long-lived host, or one
//! file ([`NetworkAuditLog::file`]) for a harness that wants the decisions of
//! exactly one run.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use serde::Serialize;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
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

/// JSONL sink for network access decisions.
///
/// Writes are handed to a background worker thread and never block the caller.
/// Cloning shares the same underlying writer and worker, and the worker flushes
/// when the last clone is dropped.
#[derive(Clone, Debug)]
pub struct NetworkAuditLog {
    writer: NonBlocking,
    _guard: Arc<WorkerGuard>,
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
        Ok(Self::with_sink(appender))
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
        Ok(Self::with_sink(file))
    }

    /// Wrap a sink in the non-blocking worker every audit log writes through.
    fn with_sink(sink: impl Write + Send + 'static) -> Self {
        let (writer, guard) = tracing_appender::non_blocking(sink);
        Self {
            writer,
            _guard: Arc::new(guard),
        }
    }

    /// Record one policy decision.
    pub fn record(&self, request: &DomainRequest, allowed: bool) {
        let record = NetworkAuditRecord {
            timestamp: humantime::format_rfc3339_millis(SystemTime::now()).to_string(),
            host: request.host(),
            port: request.port(),
            allowed,
        };
        let mut line = match serde_json::to_vec(&record) {
            Ok(line) => line,
            Err(error) => {
                tracing::error!(%error, "network audit: failed to serialize record");
                return;
            }
        };
        line.push(b'\n');
        // NonBlocking hands the buffer to a worker thread; this never blocks.
        if let Err(error) = self.writer.clone().write_all(&line) {
            tracing::error!(%error, "network audit: failed to enqueue record");
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

    async fn check(&self, request: &DomainRequest) -> bool {
        let allowed = self.inner.check(request).await;
        self.log.record(request, allowed);
        allowed
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

        // Drop the log to flush the worker thread before reading.
        drop(log);

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

        // Drop the log to flush the worker thread before reading.
        drop(log);

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
            log.record(&DomainRequest::new("example.com", 443), true);
            drop(log);
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

    // Checked at compile time: the marker decides whether a proxy runs at all,
    // so it must be a property of the type rather than of a test run.
    const _: () = assert!(Audited::<DenyAll>::DENIES_ALL);
    const _: () = assert!(!Audited::<AllowAll>::DENIES_ALL);
}
