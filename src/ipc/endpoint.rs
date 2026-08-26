//! Addressing for the IPC endpoint.
//!
//! The endpoint is a local socket, but how one is named differs by platform and
//! the difference is load-bearing for the sandbox.
//!
//! On Unix it is a filesystem socket. The path is the whole point: it is what
//! the SBPL profile and the Landlock ruleset grant access to, and its owner-only
//! permissions inside an owner-only directory are what keep other users on the
//! machine out. The abstract namespace Linux also offers has no filesystem path,
//! so no path rule could govern it; it is deliberately not used.
//!
//! On Windows the endpoint is a named pipe, which lives in a system-wide
//! namespace rather than on disk. The pipe is named after the socket file so
//! that two sandboxes never collide.

use std::io;
use std::path::Path;

use interprocess::local_socket::Name;

/// Build the local socket name for `path`.
#[cfg(unix)]
pub(crate) fn name(path: &Path) -> io::Result<Name<'static>> {
    use interprocess::local_socket::{GenericFilePath, ToFsName};

    path.to_path_buf().to_fs_name::<GenericFilePath>()
}

/// Build the local socket name for `path`.
///
/// The last two path components are used, so the per-sandbox directory name
/// that makes the socket unique is preserved in the pipe name.
#[cfg(windows)]
pub(crate) fn name(path: &Path) -> io::Result<Name<'static>> {
    use interprocess::local_socket::{GenericNamespaced, ToNsName};

    let unique = path
        .components()
        .rev()
        .take(2)
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("-");

    unique.to_ns_name::<GenericNamespaced>()
}
