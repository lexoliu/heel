//! Print the scheduling priority of the process that runs it.
//!
//! `ps` cannot answer this inside a sandbox: on macOS it is setuid root, which
//! the sandbox refuses to execute, and reading the value from `/proc` would
//! only work on Linux. A probe asks the kernel about itself instead, which is
//! the same question on both platforms.
//!
//! Output is `nice=<value> io=<value>`, where the I/O value is the raw policy
//! the platform reports: a macOS `IOPOL_*` constant, or the class-and-level
//! word Linux encodes.

/// `PRIO_PROCESS`.
const PRIO_PROCESS: i32 = 0;

#[cfg(target_os = "macos")]
/// `IOPOL_TYPE_DISK`.
const IOPOL_TYPE_DISK: i32 = 0;

#[cfg(target_os = "macos")]
/// `IOPOL_SCOPE_PROCESS`.
const IOPOL_SCOPE_PROCESS: i32 = 0;

/// `SYS_ioprio_get`, which differs per architecture.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_IOPRIO_GET: i64 = 252;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_IOPRIO_GET: i64 = 31;

/// `IOPRIO_WHO_PROCESS`.
#[cfg(target_os = "linux")]
const IOPRIO_WHO_PROCESS: i64 = 1;

extern "C" {
    fn getpriority(which: i32, who: u32) -> i32;

    #[cfg(target_os = "macos")]
    fn getiopolicy_np(iotype: i32, scope: i32) -> i32;

    #[cfg(target_os = "linux")]
    fn syscall(number: i64, ...) -> i64;
}

/// The disk I/O policy this process is subject to.
fn io_policy() -> i64 {
    #[cfg(target_os = "macos")]
    // SAFETY: both arguments are the constants this call is defined over.
    unsafe {
        i64::from(getiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS))
    }

    #[cfg(target_os = "linux")]
    // SAFETY: `ioprio_get` takes two integers and returns the priority.
    unsafe {
        syscall(SYS_IOPRIO_GET, IOPRIO_WHO_PROCESS, 0_i64)
    }
}

fn main() {
    // SAFETY: reads the calling process's own nice value.
    let nice = unsafe { getpriority(PRIO_PROCESS, 0) };
    println!("nice={nice} io={}", io_policy());
}
