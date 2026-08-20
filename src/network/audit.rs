//! Rolling audit log for sandboxed network access.
//!
//! Every policy decision — allowed or denied — is appended as one JSON line
//! to a daily-rotated log file, independent of which [`NetworkPolicy`] is in
//! force. Wrap any policy in [`Audited`] to record its verdicts.

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use serde::Serialize;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};

use crate::error::{Error, Result};
use crate::network::{ConnectionDirection, DomainRequest, NetworkPolicy};

/// One audited network access decision, serialized as a JSON line.
#[derive(Debug, Serialize)]
struct NetworkAuditRecord<'a> {
    /// RFC 3339 timestamp of the decision.
    timestamp: String,
    /// Domain or IP the sandboxed process tried to reach.
    target: &'a str,
    /// Destination port.
    port: u16,
    /// Connection direction.
    direction: &'static str,
    /// PID of the requesting process (0 when unknown).
    pid: u32,
    /// Whether the active policy allowed the connection.
    allowed: bool,
}

const fn direction_str(direction: ConnectionDirection) -> &'static str {
    match direction {
        ConnectionDirection::Inbound => "inbound",
        ConnectionDirection::Outbound => "outbound",
    }
}

/// Rolling JSONL sink for network access decisions.
///
/// Writes are handed to a background worker thread and never block the
/// caller. Log files rotate daily; at most `max_files` are kept.
/// Cloning shares the same underlying writer and worker.
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
        let (writer, guard) = tracing_appender::non_blocking(appender);
        Ok(Self {
            writer,
            _guard: Arc::new(guard),
        })
    }

    /// Record one policy decision.
    pub fn record(&self, request: &DomainRequest, allowed: bool) {
        let record = NetworkAuditRecord {
            timestamp: humantime::format_rfc3339_seconds(SystemTime::now()).to_string(),
            target: request.target(),
            port: request.port(),
            direction: direction_str(request.direction()),
            pid: request.pid(),
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
        if let Err(error) = std::io::Write::write_all(&mut self.writer.clone(), &line) {
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
            let request = DomainRequest::new(
                "api.github.com".to_string(),
                443,
                ConnectionDirection::Outbound,
                42,
            );
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
                .all(|line| line["target"] == "api.github.com" && line["port"] == 443)
        );
        assert!(lines.iter().any(|line| line["allowed"] == true));
        assert!(lines.iter().any(|line| line["allowed"] == false));
    }
}
