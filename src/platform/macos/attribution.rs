//! Attributing a process to the sandbox it runs under.
//!
//! A descendant of a sandboxed command that calls `setsid`, is reparented to
//! launchd and executes an Apple binary keeps nothing a host can read: no
//! process group, no lineage and no readable environment. What it does keep,
//! and can never drop, is the sandbox profile the kernel attached at spawn. A
//! nested `sandbox_apply` fails with `EPERM`, so every descendant stays under
//! the profile of the sandbox it started in.
//!
//! Every profile therefore denies reading one path unique to its sandbox (the
//! marker) and allows reading a second one (the control). The host asks the
//! kernel what a pid's profile says about both paths:
//!
//! - the marker is denied and the control allowed: the pid runs under this
//!   sandbox;
//! - anything else: it does not. The control is what makes this exact, because
//!   many system processes deny arbitrary paths, and a profile that denies the
//!   marker and the control both is not ours.
//!
//! Both files must exist. For a missing path the kernel answers "denied" even
//! for an unsandboxed process.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::workdir::{WorkingDir, generate_socket_dir_name};

/// Name of the file whose reading every profile of the sandbox denies.
const MARKER_NAME: &str = "marker";
/// Name of the file whose reading the profile allows.
const CONTROL_NAME: &str = "control";

/// The two paths a sandbox's profile carries.
#[derive(Debug, Clone)]
pub(crate) struct MarkerPaths {
    marker: PathBuf,
    control: PathBuf,
}

impl MarkerPaths {
    /// Marker paths inside an existing directory, for profile tests.
    #[cfg(test)]
    pub(crate) fn for_test(dir: &Path) -> Self {
        let paths = Self {
            marker: dir.join(MARKER_NAME),
            control: dir.join(CONTROL_NAME),
        };
        for path in [&paths.marker, &paths.control] {
            std::fs::write(path, b"").expect("the test marker is written");
        }
        paths
    }

    /// The path the profile denies reading.
    pub(crate) fn marker(&self) -> &Path {
        &self.marker
    }

    /// The path the profile allows reading.
    pub(crate) fn control(&self) -> &Path {
        &self.control
    }
}

/// The marker files of one sandbox, removed with it.
#[derive(Debug)]
pub(crate) struct MarkerFiles {
    paths: MarkerPaths,
    /// Declared last: dropping it removes the directory and both files.
    _dir: WorkingDir,
}

impl MarkerFiles {
    /// Create a private directory with the marker and the control file in it.
    pub(crate) fn create() -> Result<Self> {
        let dir = WorkingDir::create(&std::env::temp_dir().join(generate_socket_dir_name()), true)?;
        let paths = MarkerPaths {
            marker: dir.path().join(MARKER_NAME),
            control: dir.path().join(CONTROL_NAME),
        };
        for path in [paths.marker(), paths.control()] {
            std::fs::write(path, b"").map_err(|source| crate::Error::WorkingDir {
                path: path.to_path_buf(),
                source,
            })?;
        }
        Ok(Self { paths, _dir: dir })
    }

    /// The paths to put in the profile and to ask the kernel about.
    pub(crate) fn paths(&self) -> &MarkerPaths {
        &self.paths
    }
}

/// Whether a process runs under a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership {
    /// The process runs under this sandbox's profile, as every descendant of
    /// its commands does, whatever it did with its process group or parent.
    Member,
    /// The process is unsandboxed, or runs under another profile.
    NotMember,
    /// No process has this pid any more.
    Gone,
}

/// Why membership could not be decided.
///
/// A host that cannot get an answer must not read it as "not a member": that
/// would leave a process of the sandbox running. The fallback is the tracking
/// the host had before this API: the process group the command was spawned in
/// and the processes it can see in the lineage of the command's root.
#[derive(Debug, thiserror::Error)]
pub enum AttributionError {
    /// The running macOS does not export the SPI the answer comes from.
    #[error(
        "this macOS does not export `{symbol}`, so a process cannot be attributed to a sandbox"
    )]
    Unavailable {
        /// The missing symbol.
        symbol: &'static str,
    },
    /// The kernel refused to answer for this process.
    #[error("the kernel could not report the sandbox of process {pid}: {source}")]
    CheckFailed {
        /// The process asked about.
        pid: u32,
        /// The error `sandbox_check` reported.
        source: io::Error,
    },
    /// A marker file is gone, so the kernel would deny it for every process.
    #[error("the sandbox marker {} is missing", path.display())]
    MarkerMissing {
        /// The missing file.
        path: PathBuf,
    },
}

/// `SANDBOX_FILTER_PATH`: the filter type of an operation that names a path.
const SANDBOX_FILTER_PATH: c_int = 1;

/// The operation both paths are asked about.
const OPERATION: &[u8] = b"file-read-data\0";

/// The `sandbox_check` SPI, resolved from the running system.
///
/// **This is Apple SPI.** `sandbox_check`, `SANDBOX_CHECK_NO_REPORT` and the
/// numeric value of `SANDBOX_FILTER_PATH` come from `sandbox/private.h`, which
/// Apple does not ship in the public SDK, and they are exported by
/// `libsystem_sandbox`, which `libSystem` re-exports. They were verified on
/// macOS 27.0.1 (26A434), where `sandbox_check(pid, "file-read-data",
/// SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, path)` answers 1 for a path
/// the pid's profile denies and 0 for one it allows, for any pid of the same
/// user, and `sandbox_check(pid, NULL, 0)` answers whether the pid is
/// sandboxed at all.
///
/// The symbols are looked up at run time, not linked, so a macOS that removes
/// them turns into [`AttributionError::Unavailable`] and not into a binary
/// that no longer loads. A call that fails reports the error and never an
/// answer: the host's fallback is the process-group and lineage tracking it
/// used before, and it must not treat a failure as "not a member".
struct Spi {
    /// `int sandbox_check(pid_t pid, const char *operation, int type, ...)`.
    ///
    /// With a null operation it reports whether the pid is sandboxed; with an
    /// operation and a filter type it takes the path as the variadic argument.
    check: unsafe extern "C" fn(libc::pid_t, *const c_char, c_int, ...) -> c_int,
    /// `SANDBOX_CHECK_NO_REPORT`: keeps the question out of the system log.
    no_report: c_int,
}

impl Spi {
    fn load() -> std::result::Result<Self, AttributionError> {
        fn symbol(name: &'static str) -> std::result::Result<*mut c_void, AttributionError> {
            let c_name =
                CString::new(name).map_err(|_| AttributionError::Unavailable { symbol: name })?;
            // SAFETY: `c_name` is a valid C string and `RTLD_DEFAULT` searches
            // the images already loaded, which include `libSystem`.
            let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c_name.as_ptr()) };
            if address.is_null() {
                Err(AttributionError::Unavailable { symbol: name })
            } else {
                Ok(address)
            }
        }

        let check = symbol("sandbox_check")?;
        let no_report = symbol("SANDBOX_CHECK_NO_REPORT")?;
        Ok(Self {
            // SAFETY: the address is `sandbox_check`, declared above with the
            // signature of `sandbox/private.h`.
            check: unsafe {
                std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(libc::pid_t, *const c_char, c_int, ...) -> c_int,
                >(check)
            },
            // SAFETY: the exported symbol is an `int` constant.
            no_report: unsafe { *no_report.cast::<c_int>() },
        })
    }

    /// Whether `pid` is sandboxed at all.
    fn sandboxed(&self, pid: u32) -> std::result::Result<bool, AttributionError> {
        // SAFETY: a null operation takes no variadic argument.
        let answer = unsafe { (self.check)(pid as libc::pid_t, std::ptr::null(), 0) };
        self.answer(pid, answer)
    }

    /// Whether `pid`'s profile denies reading `path`.
    fn denies(&self, pid: u32, path: &CString) -> std::result::Result<bool, AttributionError> {
        // SAFETY: `OPERATION` is a C string, and a path filter takes exactly
        // one C string as its variadic argument.
        let answer = unsafe {
            (self.check)(
                pid as libc::pid_t,
                OPERATION.as_ptr().cast(),
                SANDBOX_FILTER_PATH | self.no_report,
                path.as_ptr(),
            )
        };
        self.answer(pid, answer)
    }

    fn answer(&self, pid: u32, answer: c_int) -> std::result::Result<bool, AttributionError> {
        match answer {
            0 => Ok(false),
            -1 => Err(AttributionError::CheckFailed {
                pid,
                source: io::Error::last_os_error(),
            }),
            _ => Ok(true),
        }
    }
}

/// Whether the process with `pid` exists.
fn exists(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    // `EPERM` means it exists and belongs to someone else.
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn c_path(path: &Path) -> std::result::Result<CString, AttributionError> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| AttributionError::MarkerMissing {
        path: path.to_path_buf(),
    })
}

/// Decide whether `pid` runs under the profile carrying `paths`.
pub(crate) fn membership(
    paths: &MarkerPaths,
    pid: u32,
) -> std::result::Result<Membership, AttributionError> {
    for path in [paths.marker(), paths.control()] {
        if !path.exists() {
            return Err(AttributionError::MarkerMissing {
                path: path.to_path_buf(),
            });
        }
    }

    if !exists(pid) {
        return Ok(Membership::Gone);
    }

    let spi = Spi::load()?;
    let decided = (|| {
        if !spi.sandboxed(pid)? {
            return Ok(Membership::NotMember);
        }
        let member = spi.denies(pid, &c_path(paths.marker())?)?
            && !spi.denies(pid, &c_path(paths.control())?)?;
        Ok(if member {
            Membership::Member
        } else {
            Membership::NotMember
        })
    })();

    match decided {
        // The process can exit between the question and the answer, and the
        // kernel then reports an error; whether it existed settles which.
        Err(AttributionError::CheckFailed { .. }) if !exists(pid) => Ok(Membership::Gone),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_files_exist_until_their_sandbox_is_gone() {
        let files = MarkerFiles::create().unwrap();
        let marker = files.paths().marker().to_path_buf();
        let control = files.paths().control().to_path_buf();
        assert!(marker.is_file() && control.is_file());

        drop(files);
        assert!(!marker.exists() && !control.exists());
        assert!(!marker.parent().unwrap().exists());
    }

    #[test]
    fn a_removed_marker_is_an_error_not_an_answer() {
        let files = MarkerFiles::create().unwrap();
        std::fs::remove_file(files.paths().marker()).unwrap();

        let error = membership(files.paths(), std::process::id()).unwrap_err();
        assert!(matches!(error, AttributionError::MarkerMissing { .. }));
    }
}
