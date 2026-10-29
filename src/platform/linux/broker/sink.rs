//! Where the broker reports what it refused.
//!
//! Landlock reports its denials to the kernel audit log, which an unprivileged
//! process cannot read. The broker sees every denial of the host protection
//! policies itself, so it records them here under the operation names the macOS
//! profile reports, and [`DenialRecorder`](crate::DenialRecorder) hands them to
//! the caller.

use std::ffi::CStr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::denial::Denial;

/// What a refused call was trying to do, named as the macOS profile names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    ReadData,
    WriteCreate,
    WriteData,
    WriteUnlink,
    WriteMode,
    WriteOwner,
    WriteTimes,
    WriteXattr,
    NetworkOutbound,
    NetworkBind,
}

impl Operation {
    /// The operation's name in a [`Denial`].
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::ReadData => "file-read-data",
            Self::WriteCreate => "file-write-create",
            Self::WriteData => "file-write-data",
            Self::WriteUnlink => "file-write-unlink",
            Self::WriteMode => "file-write-mode",
            Self::WriteOwner => "file-write-owner",
            Self::WriteTimes => "file-write-times",
            Self::WriteXattr => "file-write-xattr",
            Self::NetworkOutbound => "network-outbound",
            Self::NetworkBind => "network-bind",
        }
    }
}

/// One listener of the denials.
#[derive(Debug, Default)]
struct Subscription {
    denials: Mutex<Vec<Denial>>,
}

/// The denials of one sandbox, shared between the broker and the recorders.
#[derive(Debug, Default)]
pub(crate) struct DenialSink {
    subscribers: Mutex<Vec<Arc<Subscription>>>,
    count: AtomicUsize,
}

impl DenialSink {
    /// Start collecting denials, until the returned token is passed to
    /// [`DenialSink::finish`].
    pub(crate) fn subscribe(&self) -> Subscriber {
        let subscription = Arc::new(Subscription::default());
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::clone(&subscription));
        self.count.fetch_add(1, Ordering::Release);
        Subscriber(subscription)
    }

    /// Stop collecting and return what was collected.
    pub(crate) fn finish(&self, subscriber: &Subscriber) -> Vec<Denial> {
        let mut subscribers = self
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = subscribers.len();
        subscribers.retain(|other| !Arc::ptr_eq(other, &subscriber.0));
        if subscribers.len() != before {
            self.count.fetch_sub(1, Ordering::Release);
        }
        drop(subscribers);
        std::mem::take(
            &mut *subscriber
                .0
                .denials
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Record that `operation` on `target` was refused for the process `pid`
    /// (thread `tid`).
    pub(crate) fn record(&self, operation: Operation, target: &Path, pid: u32, tid: u32) {
        let process = std::fs::read_to_string(format!("/proc/{tid}/comm"))
            .map(|name| name.trim_end().to_owned())
            .unwrap_or_default();
        tracing::debug!(
            operation = operation.name(),
            target = %target.display(),
            pid,
            %process,
            "broker: refused"
        );
        if self.count.load(Ordering::Acquire) == 0 {
            return;
        }
        let denial = Denial {
            timestamp: local_time(),
            process,
            pid,
            operation: operation.name().to_owned(),
            target: target.display().to_string(),
            repeats: 1,
        };
        for subscriber in self
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            subscriber
                .denials
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(denial.clone());
        }
    }
}

/// A recorder's claim on the denials made after it started.
#[derive(Debug)]
pub(crate) struct Subscriber(Arc<Subscription>);

/// The current local time, as the system log writes it.
fn local_time() -> String {
    let mut seconds: libc::time_t = 0;
    // SAFETY: `time` writes the current time to the pointer it is given.
    unsafe { libc::time(&raw mut seconds) };
    // SAFETY: an all-zero `tm` is a valid destination for `localtime_r`.
    let mut broken_down: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call.
    if unsafe { libc::localtime_r(&raw const seconds, &raw mut broken_down) }.is_null() {
        return String::new();
    }
    let mut buffer = [0u8; 64];
    // SAFETY: the buffer's length is passed, the format is NUL-terminated, and
    // `broken_down` was filled in by `localtime_r`.
    let written = unsafe {
        libc::strftime(
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            c"%Y-%m-%d %H:%M:%S%z".as_ptr(),
            &raw const broken_down,
        )
    };
    CStr::from_bytes_until_nul(&buffer[..written.min(buffer.len() - 1) + 1])
        .map(|text| text.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denials_are_collected_only_between_subscribe_and_finish() {
        let sink = DenialSink::default();
        sink.record(Operation::ReadData, Path::new("/before"), 1, 1);
        let subscriber = sink.subscribe();
        sink.record(Operation::WriteCreate, Path::new("/during"), 1, 1);
        let denials = sink.finish(&subscriber);
        sink.record(Operation::ReadData, Path::new("/after"), 1, 1);

        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].operation, "file-write-create");
        assert_eq!(denials[0].target, "/during");
        assert!(sink.finish(&subscriber).is_empty());
    }
}
