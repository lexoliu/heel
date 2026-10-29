//! The pool of inodes that serves new entries in the directories above a denied
//! path.
//!
//! Landlock binds a rule to an inode and the rule follows the inode through a
//! rename. Before the sandbox is restricted, empty files and directories are
//! created that each carry the rule an entry of that directory would need, and a
//! creation directly inside such a directory is served by renaming one of them
//! into place. After that the new entry reads, executes and takes nested
//! creations like its siblings, without a rule having to be added to a ruleset
//! that is already in force.
//!
//! The pool lives on the same filesystem as the directories it serves, because a
//! rename cannot cross one. Nothing the sandbox does may reach it: the guard
//! refuses every operation inside a pool directory.

use std::collections::BTreeMap;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use landlock::{AccessFs, BitFlags};
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use crate::config::InodePool;
use crate::error::{Error, Result};
use crate::platform::linux::landlock_rules::Ancestor;

/// What a pooled inode becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Directory,
}

/// Hands the sandbox's Landlock ruleset a rule for one pooled inode.
///
/// A rule binds to the inode, and the ruleset keeps its own reference to it, so
/// the pool holds no descriptor of an entry once the rule is in.
pub(crate) type Grant<'a> = dyn FnMut(BorrowedFd<'_>, BitFlags<AccessFs>) -> Result<()> + 'a;

#[derive(Debug)]
struct Group {
    directory: PathBuf,
    held: OwnedFd,
    members: Vec<PathBuf>,
    files: Mutex<Vec<String>>,
    directories: Mutex<Vec<String>>,
}

/// An inode taken from the pool, to be renamed into place.
#[derive(Debug)]
pub(crate) struct Pooled {
    group: usize,
    kind: Kind,
    name: String,
}

/// The pre-created inodes of one sandbox.
#[derive(Debug)]
pub(crate) struct Pool {
    groups: Vec<Group>,
    capacity: InodePool,
}

fn process_is_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks that the process exists.
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Remove the pools that processes which have since exited left behind.
fn remove_stale(directory: &Path, prefix: &str) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|name| name.strip_prefix(prefix)) else {
            continue;
        };
        let pid = rest.split('-').next().and_then(|pid| pid.parse().ok());
        if pid.is_some_and(|pid| !process_is_alive(pid)) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

fn cache_directory() -> Option<PathBuf> {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::home_dir().map(|home| home.join(".cache")))
        .map(|path| path.join("heel"))
}

impl Pool {
    /// Create the pool for `ancestors`.
    ///
    /// Each entry is opened once and passed to `grant`, which adds its rule to the
    /// sandbox's own Landlock layer; the descriptor is closed at once, so the pool
    /// holds one descriptor per group however many entries it has.
    pub(crate) fn create(
        capacity: InodePool,
        ancestors: &[Ancestor],
        grant: &mut Grant<'_>,
    ) -> Result<Self> {
        let cache = cache_directory();
        if let Some(cache) = &cache {
            remove_stale(cache, "pool-");
        }
        let mut keyed: BTreeMap<(u64, u64), Vec<&Ancestor>> = BTreeMap::new();
        for ancestor in ancestors {
            let device = std::fs::metadata(&ancestor.path)
                .map_err(|error| Error::path(&ancestor.path, error))?
                .dev();
            keyed
                .entry((device, ancestor.rights.bits()))
                .or_default()
                .push(ancestor);
        }

        let mut pool = Self {
            groups: Vec::new(),
            capacity,
        };
        for ((device, _), members) in keyed {
            let rights = members
                .iter()
                .fold(BitFlags::<AccessFs>::empty(), |all, ancestor| {
                    all | ancestor.rights
                });
            let Some(directory) = locate(cache.as_deref(), device, &members) else {
                tracing::debug!(
                    device,
                    "broker: no place for an inode pool on this filesystem; new entries in its \
                     protected directories will fail"
                );
                continue;
            };
            let group = populate(directory, capacity, rights, grant, &members)?;
            pool.groups.push(group);
        }
        Ok(pool)
    }

    /// The directories the pool lives in.
    pub(crate) fn directories(&self) -> Vec<PathBuf> {
        self.groups
            .iter()
            .map(|group| group.directory.clone())
            .collect()
    }

    /// Take an inode of `kind` for a new entry in `directory`.
    ///
    /// `Err(true)` means the pool serves the directory and is out of that kind of
    /// inode; `Err(false)` that no pool serves it.
    pub(crate) fn acquire(
        &self,
        directory: &Path,
        kind: Kind,
    ) -> std::result::Result<Pooled, bool> {
        let Some(index) = self
            .groups
            .iter()
            .position(|group| group.members.iter().any(|member| member == directory))
        else {
            return Err(false);
        };
        let group = &self.groups[index];
        let list = match kind {
            Kind::File => &group.files,
            Kind::Directory => &group.directories,
        };
        let name = list
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .ok_or(true)?;
        Ok(Pooled {
            group: index,
            kind,
            name,
        })
    }

    /// Give back an inode that was not used.
    pub(crate) fn restore(&self, pooled: Pooled) {
        let group = &self.groups[pooled.group];
        let list = match pooled.kind {
            Kind::File => &group.files,
            Kind::Directory => &group.directories,
        };
        list.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(pooled.name);
    }

    /// The directory a pooled inode is in, and its name there.
    pub(crate) fn place<'a>(&'a self, pooled: &'a Pooled) -> (&'a OwnedFd, &'a str) {
        (&self.groups[pooled.group].held, &pooled.name)
    }

    /// The setting the pool's size comes from, for the message of a failure.
    pub(crate) fn describe(&self, kind: Kind) -> String {
        let (count, what) = match kind {
            Kind::File => (self.capacity.files(), "files"),
            Kind::Directory => (self.capacity.directories(), "directories"),
        };
        format!(
            "the inode pool of {count} {what} is used up; raise it with \
             SandboxConfigBuilder::inode_pool"
        )
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        for group in &self.groups {
            let _ = std::fs::remove_dir_all(&group.directory);
        }
    }
}

/// A pool directory, created and held without following any link.
struct Location {
    path: PathBuf,
    held: OwnedFd,
}

/// Open a directory as a path descriptor, refusing a link in any component.
///
/// The directories a pool lives in can be inside a tree the sandbox may write,
/// so a component swapped for a link between two steps must not move the pool.
/// Everything the pool does afterwards is relative to descriptors opened here.
fn open_directory(path: &Path) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat2(
        CWD,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
}

/// Where the pool for filesystem `device` lives: the cache directory if that is
/// on it, otherwise a hidden directory in the shallowest member that can be
/// written to.
fn locate(cache: Option<&Path>, device: u64, members: &[&Ancestor]) -> Option<Location> {
    if let Some(cache) = cache
        && std::fs::create_dir_all(cache).is_ok()
        && let Ok(root) = open_directory(cache)
        && rustix::fs::fstat(&root).is_ok_and(|stat| stat.st_dev == device)
        && let Some(pool) = create_unique(root, cache, "pool-")
    {
        return Some(pool);
    }
    let mut shallowest: Vec<&Ancestor> = members.to_vec();
    shallowest.sort_by_key(|ancestor| ancestor.path.components().count());
    for ancestor in shallowest {
        remove_stale(&ancestor.path, ".heel-pool-");
        if let Ok(root) = open_directory(&ancestor.path)
            && let Some(pool) = create_unique(root, &ancestor.path, ".heel-pool-")
        {
            return Some(pool);
        }
    }
    None
}

/// Create `<prefix><pid>-<n>` in the directory `root` holds, for the first `n`
/// nobody holds. `path` is where `root` was opened, for naming the result.
///
/// Creation is exclusive, so every pool of every sandbox in every process is a
/// directory of its own, and one that exists is never taken over: its owner is
/// alive, or its pid was reused and `remove_stale` clears it once that process
/// is gone.
fn create_unique(root: OwnedFd, path: &Path, prefix: &str) -> Option<Location> {
    let pid = std::process::id();
    for number in 0u32.. {
        let name = format!("{prefix}{pid}-{number}");
        match rustix::fs::mkdirat(&root, &name, Mode::RWXU) {
            Ok(()) => {
                let held = rustix::fs::openat(
                    &root,
                    &name,
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .ok()?;
                return Some(Location {
                    path: path.join(name),
                    held,
                });
            }
            Err(Errno::EXIST) => {}
            Err(_) => return None,
        }
    }
    None
}

fn populate(
    location: Location,
    capacity: InodePool,
    rights: BitFlags<AccessFs>,
    grant: &mut Grant<'_>,
    members: &[&Ancestor],
) -> Result<Group> {
    let Location {
        path: directory,
        held,
    } = location;
    let entry_error = |name: &str, errno: Errno| Error::path(directory.join(name), errno.into());

    let mut files = Vec::with_capacity(capacity.files());
    for number in 0..capacity.files() {
        let name = format!("f{number}");
        rustix::fs::openat(
            &held,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|errno| entry_error(&name, errno))?;
        grant(open_entry(&held, &name, &directory)?.as_fd(), rights)?;
        files.push(name);
    }
    let mut directories = Vec::with_capacity(capacity.directories());
    for number in 0..capacity.directories() {
        let name = format!("d{number}");
        rustix::fs::mkdirat(&held, &name, Mode::RWXU).map_err(|errno| entry_error(&name, errno))?;
        grant(open_entry(&held, &name, &directory)?.as_fd(), rights)?;
        directories.push(name);
    }
    Ok(Group {
        directory,
        held,
        members: members
            .iter()
            .map(|ancestor| ancestor.path.clone())
            .collect(),
        files: Mutex::new(files),
        directories: Mutex::new(directories),
    })
}

/// Open `name` in the pool directory `held` as a path descriptor that follows
/// no link. `directory` names the pool for the error.
fn open_entry(held: &OwnedFd, name: &str, directory: &Path) -> Result<OwnedFd> {
    rustix::fs::openat(
        held,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| Error::path(directory.join(name), errno.into()))
}
