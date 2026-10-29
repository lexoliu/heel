//! Resolving the paths a user wrote, once, where they enter.
//!
//! The library takes only resolved paths and never follows a link to honour a
//! grant. Whoever turns a user's spelling into a configuration (the CLI, the
//! Node bindings, an embedder) resolves it here, once. Resolution follows the
//! links the user's own spelling crosses (`/tmp`, `/var`, a symlinked home) but
//! refuses one a sandbox could have planted: a link inside a directory this
//! configuration makes writable, or as the writable path itself. Without that
//! refusal a configuration that persists across runs would re-follow, on the
//! next run, a link the previous run's sandbox put in place of a granted
//! directory.
//!
//! "Inside a directory this configuration makes writable" is decided by file
//! identity, never by how a path is spelled: each writable request is anchored
//! at the identity of the object it names, and a crossed link is refused when
//! the directory holding it, or any directory above that, is an anchor. A
//! spelling that reaches the writable directory through another link, or in
//! another case, is the same directory and meets the same rule.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Redirection, Result};

/// The number of links one path may cross before resolution gives up.
const MAX_LINKS: usize = 40;

/// A path the caller has resolved: absolute, spelled without `.` or `..`, and
/// not behind a link.
///
/// This is what a grant names. The sandbox never follows a link to honour a
/// grant, so the type carries the claim that the caller already did the
/// resolving; [`resolve_paths`] produces it for a path a user wrote, and
/// [`ResolvedPath::new`] checks one the caller already holds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolvedPath(PathBuf);

impl ResolvedPath {
    /// Accept a path that is already resolved, after checking it without
    /// following anything: it must exist, be absolute, spell no `.` or `..`
    /// component and have no component that is a link.
    ///
    /// # Errors
    ///
    /// [`Error::GrantRedirected`] when a component is a link; [`Error::Path`]
    /// when the path is relative, spells `.` or `..`, or does not exist.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        crate::platform::unresolved::verify(path)?;
        Ok(Self(path.to_path_buf()))
    }

    /// The path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// The path, owned.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl AsRef<Path> for ResolvedPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// What a configuration lets the sandbox do with a path it resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Territory {
    /// The sandbox may read it but not write it.
    ReadOnly,
    /// The sandbox may write it: a writable grant, the working directory, or a
    /// virtual environment that accepts installs.
    Writable,
}

/// One path to resolve, and what the configuration does with it.
#[derive(Debug, Clone)]
pub struct PathRequest {
    path: PathBuf,
    territory: Territory,
    missing_tail: bool,
}

impl PathRequest {
    /// A path that must exist and that the sandbox may only read.
    pub fn readable(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            territory: Territory::ReadOnly,
            missing_tail: false,
        }
    }

    /// A path that must exist and that the sandbox may write: a writable
    /// grant, the working directory, a virtual environment that accepts
    /// installs, or a persistent grant of an identity.
    pub fn writable(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            territory: Territory::Writable,
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

/// Resolve every request, pairing each result with the value it came with.
///
/// Relative paths are taken against the current directory. Links the user's
/// own spelling crosses are followed. A link is refused when it sits inside a
/// directory that a writable request names (however that request, or the link,
/// is spelled), or when a writable request is itself a link: a sandbox may have
/// planted it, and following it would move a grant to the link's target.
///
/// # Errors
///
/// [`Error::Path`] naming the path when it cannot be resolved;
/// [`Error::GrantRedirected`] naming the path when it crosses such a link.
pub fn resolve_paths<T>(
    requests: impl IntoIterator<Item = (PathRequest, T)>,
) -> Result<Vec<(ResolvedPath, T)>> {
    let walked = requests
        .into_iter()
        .map(|(request, tag)| {
            let walk = walk(&request.path, request.missing_tail)?;
            Ok((request, walk, tag))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut anchors = Vec::new();
    for (request, walk, _) in &walked {
        if request.territory == Territory::Writable {
            if walk.leaf_is_link {
                return Err(Error::GrantRedirected {
                    path: request.path.clone(),
                    reason: Redirection::SymbolicLink,
                });
            }
            // A part of the path that does not exist yet holds nothing a
            // sandbox could have planted.
            if walk.tail.is_empty() {
                anchors.push(file_id(&walk.current).map_err(|e| Error::path(&request.path, e))?);
            }
        }
    }

    let mut resolved = Vec::with_capacity(walked.len());
    for (request, walk, tag) in walked {
        refuse_planted(&request.path, &walk, &anchors)?;
        resolved.push((ResolvedPath(walk.into_resolved()), tag));
    }
    Ok(resolved)
}

/// Resolve a path the host chose itself against the writable paths of a
/// configuration that are already resolved.
///
/// The path may be spelled through links (a package manager's shim), but not
/// through one the sandbox could plant: one inside a writable directory.
pub(crate) fn resolve_outside(path: &Path, writable: &[PathBuf]) -> Result<ResolvedPath> {
    let walk = walk(path, false)?;
    let mut anchors = Vec::new();
    for writable in writable {
        match file_id(writable) {
            Ok(id) => anchors.push(id),
            // A working directory that is not created yet holds nothing.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::path(writable, error)),
        }
    }
    refuse_planted(path, &walk, &anchors)?;
    Ok(ResolvedPath(walk.into_resolved()))
}

/// Refuse the walk when it crossed a link that sits inside an anchor.
fn refuse_planted(path: &Path, walk: &Walk, anchors: &[FileId]) -> Result<()> {
    for link in &walk.links {
        // The directory holding the link, and every directory above it.
        for directory in link.ancestors().skip(1) {
            let id = file_id(directory).map_err(|source| Error::path(path, source))?;
            if anchors.contains(&id) {
                return Err(Error::GrantRedirected {
                    path: path.to_path_buf(),
                    reason: Redirection::SymbolicLink,
                });
            }
        }
    }
    Ok(())
}

/// The identity of a filesystem object: the volume it is on and its number
/// there. Two spellings of one object, in any case or through any link, give
/// the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    volume: u64,
    object: u128,
}

/// The identity of the object `path` names, without following a link in the
/// last component.
#[cfg(unix)]
fn file_id(path: &Path) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    Ok(FileId {
        volume: metadata.dev(),
        object: u128::from(metadata.ino()),
    })
}

#[cfg(windows)]
fn file_id(path: &Path) -> io::Result<FileId> {
    let (volume, object) = crate::platform::windows::acl::file_id(path)?;
    Ok(FileId { volume, object })
}

/// The outcome of walking one path.
struct Walk {
    /// The resolved part of the path, which exists: every link followed.
    current: PathBuf,
    /// The part that does not exist yet, kept as written.
    tail: Vec<OsString>,
    /// Every link the walk crossed, where it sits.
    links: Vec<PathBuf>,
    /// Whether the last component of the path as spelled is a link.
    leaf_is_link: bool,
}

impl Walk {
    fn into_resolved(mut self) -> PathBuf {
        self.current.extend(self.tail);
        self.current
    }
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

/// Resolve `path` one component at a time, recording the links it crosses.
fn walk(path: &Path, missing_tail: bool) -> Result<Walk> {
    let error = |source| Error::path(path, source);
    let absolute = std::path::absolute(path).map_err(error)?;

    let mut pending: Vec<Step> = steps(&absolute);
    pending.reverse();
    let mut current = PathBuf::new();
    let mut tail = Vec::new();
    let mut links = Vec::new();
    let mut leaf_is_link = false;

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
                        // Nothing left to walk means this is the last
                        // component as spelled, or the last of the chain its
                        // links lead to.
                        leaf_is_link |= pending.is_empty();
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

    // Every component has been inspected without following anything, so on
    // Unix the walked path is the resolved one; resolving it again would follow
    // whatever a sandbox swapped in since. Windows keeps short names and case
    // of its own, which the final path of a handle opened without following a
    // reparse point settles (the verbatim prefix `dunce` drops is dropped here
    // too, because many Win32 calls and child processes do not accept it).
    #[cfg(windows)]
    let current = crate::platform::windows::acl::final_path(&current).map_err(error)?;

    Ok(Walk {
        current,
        tail,
        links,
        leaf_is_link,
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

    /// Resolve `path` as a read-only request next to writable ones.
    fn resolve_one(path: &Path, writable: &[&Path]) -> Result<PathBuf> {
        let requests = std::iter::once(PathRequest::readable(path))
            .chain(writable.iter().map(|path| PathRequest::writable(*path)))
            .map(|request| (request, ()));
        resolve_paths(requests).map(|resolved| {
            resolved
                .into_iter()
                .next()
                .expect("the first request is resolved")
                .0
                .into_path_buf()
        })
    }

    fn resolve_writable(path: &Path) -> Result<Vec<ResolvedPath>> {
        resolve_paths([(PathRequest::writable(path), ())])
            .map(|resolved| resolved.into_iter().map(|(path, ())| path).collect())
    }

    /// `root/alias -> root/real`, and the directory `root/real/granted`, which
    /// is not a canonical way to reach it when spelled through `alias`.
    fn aliased_grant(root: &Path) -> (PathBuf, PathBuf) {
        let real = root.join("real");
        std::fs::create_dir_all(real.join("granted")).expect("creates");
        symlink(&real, root.join("alias")).expect("links");
        (root.join("alias/granted"), real.join("granted"))
    }

    /// What a sandbox does between two runs: replace `directory` with a link
    /// to `target`.
    fn swap_for_link(directory: &Path, target: &Path) {
        std::fs::remove_dir_all(directory).expect("removes");
        symlink(target, directory).expect("links");
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

        let error = resolve_writable(&granted).expect_err("planted");

        assert!(
            matches!(
                &error,
                Error::GrantRedirected { path, reason: Redirection::SymbolicLink } if *path == granted
            ),
            "{error:?}"
        );
    }

    #[test]
    fn a_granted_directory_spelled_through_a_link_above_it_and_replaced_is_refused() {
        // The spelling `alias/granted` crosses a link the user wrote, so the
        // planted link at `real/granted` is not at the path the user spelled.
        let (_guard, root) = root();
        let (spelled, resolved) = aliased_grant(&root);
        let target = root.join("target");
        std::fs::create_dir(&target).expect("creates");

        assert_eq!(
            resolve_writable(&spelled).expect("an unchanged grant resolves"),
            [ResolvedPath(resolved.clone())]
        );
        swap_for_link(&resolved, &target);
        let error = resolve_writable(&spelled).expect_err("planted");

        assert!(
            matches!(&error, Error::GrantRedirected { path, .. } if *path == spelled),
            "{error:?}"
        );
    }

    #[test]
    fn a_relative_writable_path_through_a_link_above_it_is_refused_once_replaced() {
        // The same layout reached the way a command line spells it: relative to
        // a current directory that is itself behind a link.
        let (_guard, root) = root();
        let (spelled, resolved) = aliased_grant(&root);
        let target = root.join("target");
        std::fs::create_dir(&target).expect("creates");
        swap_for_link(&resolved, &target);
        let relative = pathdiff(
            &spelled,
            &std::env::current_dir().expect("a current directory"),
        );

        let error = resolve_writable(&relative).expect_err("planted");

        assert!(matches!(error, Error::GrantRedirected { .. }), "{error:?}");
    }

    /// `path` relative to `base`, both absolute.
    fn pathdiff(path: &Path, base: &Path) -> PathBuf {
        let up = base.components().count().saturating_sub(1);
        let mut relative = PathBuf::new();
        for _ in 0..up {
            relative.push("..");
        }
        relative.extend(path.components().skip(1));
        relative
    }

    #[test]
    fn a_link_inside_a_writable_directory_reached_through_another_link_is_refused() {
        let (_guard, root) = root();
        let (writable, resolved) = aliased_grant(&root);
        let secret = root.join("secret");
        std::fs::create_dir(&secret).expect("creates");
        symlink(&secret, resolved.join("planted")).expect("links");

        // The planted link is reached as `real/granted/planted`, while the
        // writable request spells its directory as `alias/granted`.
        let error = resolve_one(&resolved.join("planted"), &[&writable]).expect_err("planted");

        assert!(matches!(error, Error::GrantRedirected { .. }), "{error:?}");
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
    fn a_link_beside_a_writable_directory_is_followed() {
        let (_guard, root) = root();
        let work = root.join("work");
        std::fs::create_dir_all(&work).expect("creates");
        std::fs::create_dir(root.join("tools")).expect("creates");
        symlink(root.join("tools"), root.join("shim")).expect("links");

        let resolved = resolve_one(&root.join("shim"), &[&work]).expect("resolves");

        assert_eq!(resolved, root.join("tools"));
    }

    #[test]
    fn the_same_directory_in_another_case_is_the_same_territory() {
        // APFS and NTFS match names without regard to case, so a spelling in
        // another case reaches the same directory and meets the same rule.
        let (_guard, root) = root();
        let writable = root.join("work");
        std::fs::create_dir_all(&writable).expect("creates");
        let shouting = root.join("WORK");
        if !shouting.exists() {
            // A case-sensitive filesystem has no second spelling to test.
            return;
        }
        let secret = root.join("secret");
        std::fs::create_dir(&secret).expect("creates");
        symlink(&secret, writable.join("planted")).expect("links");

        let error = resolve_one(&shouting.join("planted"), &[&writable]).expect_err("planted");

        assert!(matches!(error, Error::GrantRedirected { .. }), "{error:?}");
    }

    #[test]
    fn results_come_back_with_the_value_their_request_carried() {
        let (_guard, root) = root();
        let (first, second) = (root.join("first"), root.join("second"));
        std::fs::create_dir_all(&first).expect("creates");
        std::fs::create_dir_all(&second).expect("creates");

        let resolved = resolve_paths([
            (PathRequest::readable(&second), "second"),
            (PathRequest::writable(&first), "first"),
        ])
        .expect("resolves");

        assert_eq!(
            resolved,
            [
                (ResolvedPath(second), "second"),
                (ResolvedPath(first), "first")
            ]
        );
    }

    #[test]
    fn a_missing_tail_is_kept_under_its_resolved_parent() {
        let (_guard, root) = root();
        let real = root.join("real");
        std::fs::create_dir(&real).expect("creates");
        symlink(&real, root.join("link")).expect("links");

        let resolved = resolve_paths([(
            PathRequest::writable(root.join("link/a/venv")).allow_missing_tail(),
            (),
        )])
        .expect("resolves");

        assert_eq!(resolved, [(ResolvedPath(real.join("a/venv")), ())]);
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

        let error = resolve_paths([(
            PathRequest::readable(root.join("absent/..")).allow_missing_tail(),
            (),
        )])
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

    #[test]
    fn the_walked_path_is_not_resolved_a_second_time() {
        // `resolve_paths` returns the path it walked; a second resolution of it
        // would follow whatever was swapped in after the walk.
        let (_guard, root) = root();
        let (spelled, resolved) = aliased_grant(&root);

        let walked = resolve_one(&spelled, &[]).expect("resolves");

        assert_eq!(walked, resolved);
        assert!(!walked.starts_with(root.join("alias")));
    }

    #[test]
    fn a_path_outside_the_writable_directories_is_resolved_for_the_host() {
        let (_guard, root) = root();
        let (writable, resolved) = aliased_grant(&root);
        std::fs::write(root.join("real/tool"), "").expect("writes");
        symlink(root.join("real/tool"), root.join("shim")).expect("links");

        let followed = resolve_outside(&root.join("shim"), std::slice::from_ref(&resolved))
            .expect("a shim beside the writable directory is followed");
        assert_eq!(followed.as_path(), root.join("real/tool"));

        symlink(root.join("real/tool"), resolved.join("planted")).expect("links");
        let error = resolve_outside(&writable.join("planted"), &[resolved])
            .expect_err("a link inside the writable directory is refused");
        assert!(matches!(error, Error::GrantRedirected { .. }), "{error:?}");
    }

    #[test]
    fn a_resolved_path_is_checked_when_it_is_made() {
        let (_guard, root) = root();
        let (spelled, real) = aliased_grant(&root);

        ResolvedPath::new(&real).expect("a resolved path is accepted");
        for refused in [spelled, PathBuf::from("relative"), root.join("absent")] {
            assert!(
                ResolvedPath::new(&refused).is_err(),
                "{} must be refused",
                refused.display()
            );
        }
    }
}
