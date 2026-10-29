//! Verification that a granted path is still the path the caller resolved.
//!
//! A grant names a path the caller has already resolved. Resolving it again at
//! every build would let a sandboxed process that can write a granted
//! directory's parent swap the directory for a link and have the next sandbox
//! grant the link's target. The check here walks the path one component at a
//! time without following anything and refuses the grant if a component is a
//! link, so the path is then emitted exactly as given.

use std::io;
use std::path::Path;

use crate::error::{Error, Result};

/// Fail unless `path` is absolute, in normal form, and no component of it is a
/// link.
///
/// A name-surrogate reparse point (a symbolic link or a junction on Windows) is
/// a link; other reparse points, such as cloud placeholders, redirect nothing
/// and are not.
///
/// # Errors
///
/// [`Error::GrantRedirected`] when a component is a link; [`Error::Path`] when
/// the path is relative, spells a `.` or `..` component, or a component cannot
/// be inspected, a missing one included.
pub(crate) fn verify(path: &Path) -> Result<()> {
    require_normal(path)?;

    for component in path.ancestors() {
        let metadata = std::fs::symlink_metadata(component).map_err(|e| Error::path(path, e))?;
        if metadata.file_type().is_symlink() {
            return Err(Error::GrantRedirected {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Fail unless `path` is absolute and spells no `.` or `..` component.
///
/// The macOS profile names a path as text and the kernel matches it against
/// resolved paths, so a non-normal spelling would build a sandbox that grants
/// nothing; the other backends reject it too so the three agree.
pub(crate) fn require_normal(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::path(
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a grant names an absolute, already resolved path",
            ),
        ));
    }

    // `Path::components` drops an interior `.`, so the spelling is read as text.
    let text = path.to_string_lossy();
    if text
        .split(std::path::is_separator)
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(Error::path(
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a grant names a path without `.` or `..` components",
            ),
        ));
    }
    Ok(())
}

/// A temporary directory at its resolved path, which is what a grant names.
///
/// The system temp directory can sit behind a link (`/var` on macOS) or spell a
/// short name (`RUNNER~1` on Windows), neither of which a grant may.
#[cfg(test)]
pub(crate) fn resolved_tempdir() -> tempfile::TempDir {
    let root = dunce::canonicalize(std::env::temp_dir()).expect("the temp directory resolves");
    tempfile::Builder::new()
        .tempdir_in(root)
        .expect("a temporary directory")
}

/// Make `link` a junction to `target`: what a sandboxed process can plant on
/// Windows without any privilege.
#[cfg(all(test, windows))]
pub(crate) fn junction(link: &Path, target: &Path) {
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .expect("cmd runs");
    assert!(
        output.status.success(),
        "mklink: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_link_anywhere_in_the_path_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(root.path()).expect("resolves");
        let real = root.join("real");
        std::fs::create_dir_all(real.join("inner")).expect("creates");
        std::os::unix::fs::symlink(&real, root.join("link")).expect("links");

        verify(&real.join("inner")).expect("an unchanged path verifies");
        for through in [root.join("link"), root.join("link").join("inner")] {
            assert!(
                matches!(verify(&through), Err(Error::GrantRedirected { .. })),
                "{} must be refused",
                through.display()
            );
        }
    }

    #[test]
    fn dot_and_dot_dot_components_are_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(root.path()).expect("resolves");
        std::fs::create_dir(root.join("b")).expect("creates");

        for spelling in ["a/../b", "./b", "b/.", "b/.."] {
            let path = root.join(spelling);
            assert!(
                matches!(verify(&path), Err(Error::Path { .. })),
                "{} must be refused",
                path.display()
            );
        }
        verify(&root.join("b")).expect("the normal spelling verifies");
    }

    #[test]
    fn a_relative_or_missing_path_is_an_error() {
        let root = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            verify(Path::new("relative")),
            Err(Error::Path { .. })
        ));
        assert!(matches!(
            verify(&root.path().join("absent")),
            Err(Error::Path { .. })
        ));
    }
}
