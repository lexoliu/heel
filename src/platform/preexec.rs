//! What the Unix backends apply between `fork` and `exec`.
//!
//! Resource limits and scheduling priority are both set on the process after
//! it forks and before it execs, so they cover the sandboxed process and every
//! descendant it creates. Both are flattened into plain integers beforehand:
//! the post-fork path is allowed to issue syscalls and nothing else, so it must
//! not allocate, lock, or read a configuration.

use std::io;

use crate::config::SandboxConfigData;
use crate::platform::rlimit::PreparedLimits;
use crate::priority::{CpuPriority, IoPriority, ProcessPriority};

/// Everything one `pre_exec` hook installs, prepared before the fork.
#[derive(Debug)]
pub(crate) struct PreExecSetup {
    limits: PreparedLimits,
    priority: PreparedPriority,
}

impl PreExecSetup {
    /// Flatten a configuration into the syscalls to issue after forking.
    pub(crate) fn new(config: &SandboxConfigData) -> Self {
        Self {
            limits: PreparedLimits::new(config.limits()),
            priority: PreparedPriority::new(config.priority()),
        }
    }

    /// Whether there is nothing to install.
    ///
    /// A `pre_exec` hook rules out the `posix_spawn` fast path, so a backend
    /// with nothing to apply installs none. Only macOS has that choice: the
    /// Linux hook also carries Landlock and seccomp, which are never absent.
    #[cfg(target_os = "macos")]
    pub(crate) fn is_empty(&self) -> bool {
        self.limits.is_empty() && self.priority.is_empty()
    }

    /// Install everything on the current process.
    ///
    /// Safe to call from `pre_exec`: it only issues `setrlimit`, `setpriority`
    /// and the platform's I/O priority syscall.
    pub(crate) fn apply(&self) -> io::Result<()> {
        self.limits.apply()?;
        self.priority.apply()
    }
}

/// A scheduling priority, flattened into the arguments its syscalls take.
///
/// The I/O policy is stored as the raw value the platform's call expects,
/// because the two platforms disagree on both the call and the encoding and
/// neither translation may happen after the fork.
#[derive(Debug, Clone, Copy)]
struct PreparedPriority {
    nice: Option<libc::c_int>,
    io_policy: Option<libc::c_int>,
}

impl PreparedPriority {
    /// Flatten a configured priority.
    fn new(priority: ProcessPriority) -> Self {
        let nice = match priority.cpu() {
            CpuPriority::Normal => None,
            CpuPriority::Nice(level) => Some(libc::c_int::from(level.get())),
        };

        Self {
            nice,
            io_policy: io_policy(priority.io()),
        }
    }

    /// Whether neither half was lowered; see [`PreExecSetup::is_empty`].
    #[cfg(target_os = "macos")]
    fn is_empty(self) -> bool {
        self.nice.is_none() && self.io_policy.is_none()
    }

    /// Lower the current process's priority.
    fn apply(self) -> io::Result<()> {
        if let Some(nice) = self.nice {
            // SAFETY: `setpriority` takes three integers, is async-signal-safe
            // and allocates nothing, as `pre_exec` requires.
            let result = unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, nice) };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if let Some(policy) = self.io_policy {
            set_io_policy(policy)?;
        }

        Ok(())
    }
}

/// macOS I/O policies, from `<sys/resource.h>`.
///
/// `setiopolicy_np` is a documented macOS call that `libc` has no binding for,
/// so it and the constants it takes are declared here against that header.
///
/// The disk policy is lowered on its own rather than through a QoS class or
/// `PRIO_DARWIN_BG`, both of which also confine the process to the efficiency
/// cores: the point is to yield when something else wants the machine, not to
/// run the work on a fraction of it.
#[cfg(target_os = "macos")]
mod darwin {
    use libc::c_int;

    /// `IOPOL_TYPE_DISK`.
    pub(super) const IOPOL_TYPE_DISK: c_int = 0;
    /// `IOPOL_SCOPE_PROCESS`, so descendants inherit the policy.
    pub(super) const IOPOL_SCOPE_PROCESS: c_int = 0;
    /// `IOPOL_THROTTLE`: runs only on bandwidth nothing else is using.
    pub(super) const IOPOL_THROTTLE: c_int = 3;
    /// `IOPOL_UTILITY`: yields to interactive work without being throttled.
    pub(super) const IOPOL_UTILITY: c_int = 4;

    unsafe extern "C" {
        /// `int setiopolicy_np(int iotype, int scope, int policy)`.
        pub(super) fn setiopolicy_np(iotype: c_int, scope: c_int, policy: c_int) -> c_int;

        /// `int getiopolicy_np(int iotype, int scope)`, which only the tests
        /// need: they assert on what a forked child actually ended up with.
        #[cfg(test)]
        pub(super) fn getiopolicy_np(iotype: c_int, scope: c_int) -> c_int;
    }
}

/// The raw I/O policy for a configured priority, or `None` to leave it alone.
#[cfg(target_os = "macos")]
fn io_policy(priority: IoPriority) -> Option<libc::c_int> {
    match priority {
        IoPriority::Normal => None,
        IoPriority::Utility => Some(darwin::IOPOL_UTILITY),
        IoPriority::Background => Some(darwin::IOPOL_THROTTLE),
    }
}

/// Lower the current process's disk I/O policy.
#[cfg(target_os = "macos")]
fn set_io_policy(policy: libc::c_int) -> io::Result<()> {
    // SAFETY: the three arguments are the constants this call is defined over,
    // and it allocates nothing, as `pre_exec` requires.
    let result = unsafe {
        darwin::setiopolicy_np(darwin::IOPOL_TYPE_DISK, darwin::IOPOL_SCOPE_PROCESS, policy)
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// The current process's disk I/O policy.
#[cfg(all(test, target_os = "macos"))]
fn current_io_policy() -> libc::c_int {
    // SAFETY: both arguments are the constants this call is defined over.
    unsafe { darwin::getiopolicy_np(darwin::IOPOL_TYPE_DISK, darwin::IOPOL_SCOPE_PROCESS) }
}

/// Linux I/O priorities, from `include/uapi/linux/ioprio.h`.
///
/// `ioprio_set` has no libc wrapper on any platform, so it goes through
/// `syscall` with the encoding the kernel documents.
#[cfg(target_os = "linux")]
mod ioprio {
    use libc::c_int;

    /// `IOPRIO_WHO_PROCESS`.
    pub(super) const WHO_PROCESS: c_int = 1;
    /// `IOPRIO_CLASS_SHIFT`: the class occupies the top three bits.
    const CLASS_SHIFT: c_int = 13;
    /// `IOPRIO_CLASS_BE`, the class ordinary processes are in.
    const CLASS_BEST_EFFORT: c_int = 2;
    /// `IOPRIO_CLASS_IDLE`: served only when the disk is otherwise idle.
    const CLASS_IDLE: c_int = 3;
    /// The lowest level within a class.
    const LOWEST_LEVEL: c_int = 7;

    /// `IOPRIO_PRIO_VALUE`.
    const fn value(class: c_int, level: c_int) -> c_int {
        (class << CLASS_SHIFT) | level
    }

    /// Best effort at its lowest level: still served, but after everything.
    pub(super) const UTILITY: c_int = value(CLASS_BEST_EFFORT, LOWEST_LEVEL);
    /// The idle class, which waits for the disk to have nothing else to do.
    pub(super) const BACKGROUND: c_int = value(CLASS_IDLE, 0);
}

/// The raw I/O priority for a configured priority, or `None` to leave it alone.
#[cfg(target_os = "linux")]
fn io_policy(priority: IoPriority) -> Option<libc::c_int> {
    match priority {
        IoPriority::Normal => None,
        IoPriority::Utility => Some(ioprio::UTILITY),
        IoPriority::Background => Some(ioprio::BACKGROUND),
    }
}

/// Lower the current process's I/O priority.
#[cfg(target_os = "linux")]
fn set_io_policy(policy: libc::c_int) -> io::Result<()> {
    // SAFETY: `ioprio_set` takes three integers and returns one; it is a bare
    // syscall that allocates nothing, as `pre_exec` requires.
    let result = unsafe { libc::syscall(libc::SYS_ioprio_set, ioprio::WHO_PROCESS, 0, policy) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// The current process's I/O priority, in the kernel's encoding.
#[cfg(all(test, target_os = "linux"))]
fn current_io_policy() -> libc::c_int {
    // SAFETY: `ioprio_get` takes the same two leading arguments as
    // `ioprio_set` and returns the priority as its result.
    let result = unsafe { libc::syscall(libc::SYS_ioprio_get, ioprio::WHO_PROCESS, 0) };
    libc::c_int::try_from(result).unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use crate::config::{ResourceLimits, SandboxConfig, SandboxConfigBuilder};
    use crate::priority::NiceLevel;

    /// The policy-independent data of a configuration built by `configure`.
    #[cfg(target_os = "macos")]
    fn config(configure: impl FnOnce(SandboxConfigBuilder) -> SandboxConfig) -> SandboxConfigData {
        configure(SandboxConfig::builder()).data().clone()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_default_configuration_installs_nothing() {
        // The `posix_spawn` fast path depends on this: a hook that applies
        // nothing still costs a fork.
        assert!(PreExecSetup::new(&config(|builder| builder.build())).is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn either_half_on_its_own_needs_a_hook() {
        let limited = config(|builder| {
            builder
                .limits(ResourceLimits::builder().max_processes(8).build())
                .build()
        });
        assert!(!PreExecSetup::new(&limited).is_empty());

        let niced = config(|builder| {
            builder
                .priority(ProcessPriority::new(
                    CpuPriority::Nice(NiceLevel::HIGHEST),
                    IoPriority::Normal,
                ))
                .build()
        });
        assert!(!PreExecSetup::new(&niced).is_empty());

        let throttled = config(|builder| {
            builder
                .priority(ProcessPriority::new(
                    CpuPriority::Normal,
                    IoPriority::Background,
                ))
                .build()
        });
        assert!(!PreExecSetup::new(&throttled).is_empty());
    }

    #[test]
    fn a_normal_priority_prepares_no_syscall() {
        let prepared = PreparedPriority::new(ProcessPriority::default());
        assert_eq!(prepared.nice, None);
        assert_eq!(prepared.io_policy, None);
    }

    #[test]
    fn a_lowered_priority_prepares_both_syscalls() {
        let prepared = PreparedPriority::new(ProcessPriority::new(
            CpuPriority::Nice(NiceLevel::new(7).unwrap()),
            IoPriority::Utility,
        ));

        assert_eq!(prepared.nice, Some(7));
        assert!(prepared.io_policy.is_some());
    }

    #[test]
    fn a_forked_child_keeps_what_was_applied() {
        // A fork is how this runs for real: `pre_exec` executes in a child
        // that may only issue syscalls, so the test takes the same path and
        // reads both values back from where they were set.
        //
        // The largest level is the one every host can reach: raising priority
        // is refused, and the process running the tests may itself be niced.
        let expected_nice = libc::c_int::from(NiceLevel::HIGHEST.get());
        let prepared = PreparedPriority::new(ProcessPriority::new(
            CpuPriority::Nice(NiceLevel::HIGHEST),
            IoPriority::Utility,
        ));
        let expected_io = prepared.io_policy.unwrap();

        // SAFETY: the child below issues syscalls and then `_exit`s, never
        // returning to the test harness, which is what a fork from a
        // multi-threaded process requires.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());

        if pid == 0 {
            let applied = prepared.apply().is_ok();
            // SAFETY: reads the calling process's own nice value.
            let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS as _, 0) };
            let observed_io = current_io_policy();
            let agreed = applied && nice == expected_nice && observed_io == expected_io;
            // SAFETY: ends the child without running any destructor or
            // `atexit` handler the parent's threads are still using.
            unsafe { libc::_exit(i32::from(!agreed)) };
        }

        let mut status = 0;
        // SAFETY: `status` is a valid destination and `pid` is the child above.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert_eq!(waited, pid, "waiting for the child must succeed");
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the child did not observe the priority it applied: status {status}"
        );
    }
}
