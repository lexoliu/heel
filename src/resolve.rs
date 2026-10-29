//! Resolving the paths a user wrote, once, where they enter.
//!
//! The library takes only resolved paths and never follows a link to honour a
//! grant. Whoever turns a user's spelling into a configuration (the CLI, the
//! Node bindings, an embedder) resolves it here, once. Resolution follows the
//! links the user's own spelling crosses (`/tmp`, `/var`, a symlinked home) but
//! refuses one a sandbox could have planted: a link at or below a path this
//! configuration makes writable. Without that refusal a configuration that
//! persists across runs would re-follow, on the next run, a link the previous
//! run's sandbox put in place of a granted directory.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// The number of links one path may cross before resolution gives up.
const MAX_LINKS: usize = 40;

/// One path to resolve, and what the configuration does with it.
#[derive(Debug, Clone)]
pub struct PathRequest {
    path: PathBuf,
    writable: bool,
    missing_tail: bool,
}

impl PathRequest {
    /// A path that must exist. `writable` says whether the configuration lets
    /// the sandbox write it: a writable grant, the working directory, or a
    /// virtual environment that accepts installs.
    pub fn new(path: impl Into<PathBuf>, writable: bool) -> Self {
        Self {
            path: path.into(),
            writable,
            missing_tail: false,
        }
    }

    /// Accept a path whose last components do not exist yet, such as a working
    /// directory the sandbox creates. The existing part is resolved and the
    /// rest is kept as written, so it must name plain components.
    #[must_use]
    pub fn allow_missing_tail(mut self) -> Self {
        self.missing_tail = true;
        self
    }
}

/// Resolve every request, in order.
///
/// Relative paths are taken against the current directory. A path crossing a
/// link that sits at or below a writable path of this configuration (the
/// writable paths as the user spelled them and as they resolve) is refused.
///
/// # Errors
///
/// [`Error::Path`] naming the path when it cannot be resolved;
/// [`Error::GrantRedirected`] naming the path when it crosses such a link.
pub fn resolve_paths(requests: &[PathRequest]) -> Result<Vec<PathBuf>> {
    let walks = requests
        .iter()
        .map(|request| walk(&request.path, request.missing_tail))
        .collect::<Result<Vec<_>>>()?;

    let territory: Vec<&Path> = requests
        .iter()
        .zip(&walks)
        .filter(|(request, _)| request.writable)
        .flat_map(|(_, walk)| [walk.lexical.as_path(), walk.resolved.as_path()])
        .collect();

    for (request, walk) in requests.iter().zip(&walks) {
        refuse_planted(&request.path, walk, &territory)?;
    }

    Ok(walks.into_iter().map(|walk| walk.resolved).collect())
}

/// Resolve a path the host chose itself against the writable paths of a
/// configuration that are already resolved.
///
/// The path may be spelled through links (a package manager's shim), but not
/// through one the sandbox could plant.
pub(crate) fn resolve_outside(path: &Path, writable: &[&Path]) -> Result<PathBuf> {
    let walk = walk(path, false)?;
    refuse_planted(path, &walk, writable)?;
    Ok(walk.resolved)
}

fn refuse_planted(path: &Path, walk: &Walk, territory: &[&Path]) -> Result<()> {
    if walk
        .links
        .iter()
        .any(|link| territory.iter().any(|writable| link.starts_with(writable)))
    {
        return Err(Error::GrantRedirected {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// The outcome of walking one path.
struct Walk {
    /// The path with `.` and `..` removed lexically, as the user spelled it.
    lexical: PathBuf,
    /// The path with every link followed.
    resolved: PathBuf,
    /// Every link the walk crossed, where it sits.
    links: Vec<PathBuf>,
}

/// One step of a path being walked.
enum Step {
    Root(OsString),
    Parent,
    Name(OsString),
}

fn steps(path: &Path) -> Vec<Step> {
    path.components()
        .filter_map(|component| match component {
            Component::Prefix(_) | Component::RootDir => {
                Some(Step::Root(component.as_os_str().to_owned()))
            }
            Component::CurDir => None,
            Component::ParentDir => Some(Step::Parent),
            Component::Normal(name) => Some(Step::Name(name.to_owned())),
        })
        .collect()
}

fn lexical(absolute: &Path) -> PathBuf {
    let mut lexical = PathBuf::new();
    for step in steps(absolute) {
        match step {
            Step::Root(root) => lexical.push(root),
            Step::Parent => {
                lexical.pop();
            }
            Step::Name(name) => lexical.push(name),
        }
    }
    lexical
}

/// Resolve `path` one component at a time, recording the links it crosses.
fn walk(path: &Path, missing_tail: bool) -> Result<Walk> {
    let error = |source| Error::path(path, source);
    let absolute = std::path::absolute(path).map_err(error)?;

    let mut pending: Vec<Step> = steps(&absolute);
    pending.reverse();
    let mut current = PathBuf::new();
    let mut tail = Vec::new();
    let mut links = Vec::new();

    while let Some(step) = pending.pop() {
        match step {
            Step::Root(root) => current.push(root),
            Step::Parent => {
                current.pop();
            }
            Step::Name(name) => {
                current.push(&name);
                match std::fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        if links.len() == MAX_LINKS {
                            return Err(error(io::Error::other("too many levels of links")));
                        }
                        let target = std::fs::read_link(&current).map_err(error)?;
                        links.push(current.clone());
                        current.pop();
                        pending.extend(steps(&target).into_iter().rev());
                    }
                    Ok(_) => {}
                    Err(source) if missing_tail && source.kind() == io::ErrorKind::NotFound => {
                        // The rest does not exist, so there is nothing to
                        // follow: it is kept as written.
                        current.pop();
                        tail.push(name);
                        while let Some(step) = pending.pop() {
                            match step {
                                Step::Name(name) => tail.push(name),
                                Step::Root(_) | Step::Parent => {
                                    return Err(error(io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "the part of the path that does not exist yet must name \
                                         plain components",
                                    )));
                                }
                            }
                        }
                    }
                    Err(source) => return Err(error(source)),
                }
            }
        }
    }

    // The walk has followed every link, so this settles only the spelling the
    // platform keeps its own (case, short names, a verbatim prefix `dunce`
    // drops because many Win32 calls and child processes do not accept it).
    let mut resolved = dunce::canonicalize(&current).map_err(error)?;
    resolved.extend(tail);

    Ok(Walk {
        lexical: lexical(&absolute),
        resolved,
        links,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    /// A directory at its resolved path.
    fn root() -> (tempfile::TempDir, PathBuf) {
        let dir = crate::platform::unresolved::resolved_tempdir();
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    fn resolve_one(path: &Path, writable: &[&Path]) -> Result<PathBuf> {
        let mut requests = vec![PathRequest::new(path, false)];
        requests.extend(writable.iter().map(|path| PathRequest::new(*path, true)));
        resolve_paths(&requests).map(|mut resolved| resolved.swap_remove(0))
    }

    #[test]
    fn a_link_outside_writable_territory_is_followed() {
        let (_guard, root) = root();
        let real = root.join("real");
        std::fs::create_dir_all(real.join("inner")).expect("creates");
        symlink(&real, root.join("link")).expect("links");

        let resolved = resolve_one(&root.join("link/inner"), &[]).expect("resolves");

        assert_eq!(resolved, real.join("inner"));
    }

    #[test]
    fn dots_are_normalised_after_the_links_before_them_are_followed() {
        let (_guard, root) = root();
        let real = root.join("real");
        std::fs::create_dir_all(real.join("inner")).expect("creates");
        std::fs::create_dir(root.join("other")).expect("creates");
        symlink(real.join("inner"), root.join("link")).expect("links");

        let resolved = resolve_one(&root.join("link/../inner/./"), &[]).expect("resolves");

        assert_eq!(resolved, real.join("inner"));
    }

    #[test]
    fn a_granted_directory_replaced_by_a_link_is_refused() {
        let (_guard, root) = root();
        let granted = root.join("granted");
        let target = root.join("target");
        std::fs::create_dir_all(&target).expect("creates");
        symlink(&target, &granted).expect("links");

        let error = resolve_paths(&[PathRequest::new(&granted, true)]).expect_err("planted");

        assert!(
            matches!(&error, Error::GrantRedirected { path } if *path == granted),
            "{error:?}"
        );
    }

    #[test]
    fn a_link_below_another_writable_path_is_refused_for_any_request() {
        let (_guard, root) = root();
        let work = root.join("work");
        let target = root.join("target");
        std::fs::create_dir_all(&work).expect("creates");
        std::fs::create_dir_all(&target).expect("creates");
        symlink(&target, work.join("planted")).expect("links");

        let error = resolve_one(&work.join("planted"), &[&work]).expect_err("planted");

        assert!(matches!(error, Error::GrantRedirected { .. }), "{error:?}");
    }

    #[test]
    fn a_missing_tail_is_kept_under_its_resolved_parent() {
        let (_guard, root) = root();
        let real = root.join("real");
        std::fs::create_dir(&real).expect("creates");
        symlink(&real, root.join("link")).expect("links");

        let resolved =
            resolve_paths(&[PathRequest::new(root.join("link/a/venv"), true).allow_missing_tail()])
                .expect("resolves");

        assert_eq!(resolved, [real.join("a/venv")]);
    }

    #[test]
    fn a_missing_path_without_the_allowance_names_itself() {
        let (_guard, root) = root();
        let missing = root.join("absent");

        let error = resolve_one(&missing, &[]).expect_err("must exist");

        assert!(
            matches!(&error, Error::Path { path, .. } if *path == missing),
            "{error:?}"
        );
    }

    #[test]
    fn a_trailing_parent_component_cannot_be_part_of_a_missing_tail() {
        let (_guard, root) = root();

        let error =
            resolve_paths(&[PathRequest::new(root.join("absent/.."), false).allow_missing_tail()])
                .expect_err("cannot resolve");

        assert!(matches!(error, Error::Path { .. }), "{error:?}");
    }

    #[test]
    fn a_cycle_of_links_is_an_error() {
        let (_guard, root) = root();
        symlink(root.join("b"), root.join("a")).expect("links");
        symlink(root.join("a"), root.join("b")).expect("links");

        let error = resolve_one(&root.join("a"), &[]).expect_err("a cycle");

        assert!(matches!(error, Error::Path { .. }), "{error:?}");
    }

    #[test]
    fn a_relative_path_resolves_against_the_current_directory() {
        let resolved = resolve_one(Path::new("."), &[]).expect("resolves");

        assert!(resolved.is_absolute(), "{resolved:?}");
    }
}
