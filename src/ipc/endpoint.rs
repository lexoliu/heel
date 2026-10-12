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
#[cfg(windows)]
pub(crate) fn name(path: &Path) -> io::Result<Name<'static>> {
    use interprocess::local_socket::{GenericNamespaced, ToNsName};

    pipe_name(path).to_ns_name::<GenericNamespaced>()
}

/// The name the pipe bound for `path` carries in `\\.\pipe\`.
///
/// The complete native path is hashed so nested socket directories preserve
/// sandbox identity within the system-wide pipe namespace.
#[cfg(windows)]
pub(crate) fn pipe_name(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::os::windows::ffi::OsStrExt;

    let bytes = path
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    format!("heel-{:x}", Sha256::digest(bytes))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn nested_socket_paths_retain_the_sandbox_identity() {
        let first = Path::new(r"C:\Temp\heel-first\socket\s");
        let second = Path::new(r"C:\Temp\heel-second\socket\s");
        assert_ne!(pipe_name(first), pipe_name(second));
        assert_eq!(pipe_name(first), pipe_name(first));
    }
}
