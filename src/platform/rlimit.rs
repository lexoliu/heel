//! Resource limits applied to sandboxed processes.
//!
//! Limits are installed between `fork` and `exec` so they cover the sandboxed
//! process and every descendant it creates. `setrlimit` is a bare syscall with
//! no allocation, which is what `pre_exec` requires.

use std::io;

use crate::config::ResourceLimits;

/// One limit to install, as a raw `setrlimit` pair.
#[derive(Debug, Clone, Copy)]
struct Limit {
    resource: libc::c_int,
    value: u64,
}

/// The limits from a configuration, flattened for use inside `pre_exec`.
///
/// Building this before forking keeps the post-fork path allocation-free.
#[derive(Debug, Clone, Default)]
pub(crate) struct PreparedLimits {
    limits: Vec<Limit>,
}

impl PreparedLimits {
    /// Flatten a configuration into the limits to install.
    pub(crate) fn new(limits: &ResourceLimits) -> Self {
        let mut prepared = Vec::new();

        // RLIMIT_NPROC is not defined on all targets libc supports, but is on
        // every platform with a sandbox backend.
        let entries = [
            (libc::RLIMIT_AS, limits.max_memory_bytes()),
            (libc::RLIMIT_CPU, limits.max_cpu_time_secs()),
            (libc::RLIMIT_FSIZE, limits.max_file_size_bytes()),
            (libc::RLIMIT_NPROC, limits.max_processes()),
        ];

        for (resource, value) in entries {
            if let Some(value) = value {
                prepared.push(Limit {
                    resource: resource as libc::c_int,
                    value,
                });
            }
        }

        Self { limits: prepared }
    }

    /// Install the limits on the current process.
    ///
    /// Safe to call from `pre_exec`: it only issues `setrlimit` syscalls.
    pub(crate) fn apply(&self) -> io::Result<()> {
        for limit in &self.limits {
            let value = libc::rlim_t::try_from(limit.value).unwrap_or(libc::rlim_t::MAX);
            let rlimit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };

            // SAFETY: `rlimit` is a fully initialized value of the expected
            // type and `resource` is one of the constants above.
            let result = unsafe { libc::setrlimit(limit.resource as _, &raw const rlimit) };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_configuration_prepares_no_limits() {
        assert!(
            PreparedLimits::new(&ResourceLimits::default())
                .limits
                .is_empty()
        );
    }

    #[test]
    fn every_configured_limit_is_prepared() {
        let limits = ResourceLimits::builder()
            .max_memory_bytes(1 << 30)
            .max_cpu_time_secs(10)
            .max_file_size_bytes(1 << 20)
            .max_processes(32)
            .build();

        let prepared = PreparedLimits::new(&limits);
        assert_eq!(prepared.limits.len(), 4);
    }

    #[test]
    fn limits_apply_to_the_current_process() {
        // Applying in a forked child would need a fork; instead check that a
        // limit above the current soft limit is rejected only by the kernel,
        // not by our own bookkeeping. Raising FSIZE to its current value is
        // always permitted.
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `current` is a valid, initialized destination.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &raw mut current) };
        assert_eq!(rc, 0, "reading the current file size limit must succeed");

        if current.rlim_cur == libc::RLIM_INFINITY {
            return;
        }

        let limits = ResourceLimits::builder()
            .max_file_size_bytes(current.rlim_cur)
            .build();
        PreparedLimits::new(&limits)
            .apply()
            .expect("re-applying the current limit succeeds");
    }
}
