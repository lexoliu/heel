//! What the broker refuses: the host protection policies as the broker applies
//! them, by name and by inode, to paths it has already resolved.
//!
//! Every path handed to these checks is a real path (no symbolic links, no `..`)
//! because it was read back from a descriptor the broker holds. The denied trees
//! are canonicalized the same way, and also taken under every other mount of the
//! same filesystem, since a bind mount shows one directory under two names.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::SandboxConfigData;
use crate::error::Result;
use crate::platform::linux::landlock_rules;
use crate::policy::{Pattern, Resolved};

/// A device and inode number.
pub(crate) type InodeId = (u64, u64);

/// The write side of the policy.
#[derive(Debug, Default)]
struct WriteRules {
    trees: Vec<PathBuf>,
    patterns: Vec<Pattern>,
    exempt: Vec<PathBuf>,
    guarded_parents: Vec<PathBuf>,
    /// The directories that hold a match of a pattern, with the pattern.
    pattern_parents: Vec<Pattern>,
}

/// What the broker enforces for one sandbox.
#[derive(Debug, Default)]
pub(crate) struct Guard {
    read_trees: Vec<PathBuf>,
    /// The paths the configuration names, under every name they have. One that
    /// is, or lies inside, a read tree opens the part of it that it names.
    named: Vec<PathBuf>,
    /// The locations the security toggles protect, wherever they are found.
    protected: Vec<Pattern>,
    read_guarded_parents: Vec<PathBuf>,
    write: WriteRules,
    inodes: HashSet<InodeId>,
    socket_paths: Vec<PathBuf>,
    socket_inodes: HashSet<InodeId>,
    runtime_dir: Option<PathBuf>,
    ipc_socket: Option<PathBuf>,
    /// Directories on the way to a denied path, whose new entries are served
    /// from the pool.
    ancestors: HashSet<PathBuf>,
    pool_dirs: Vec<PathBuf>,
    /// For each directory, the names directly inside it that are denied.
    denied_children: HashMap<PathBuf, Vec<Vec<u8>>>,
    reads_denied: bool,
    writes_denied: bool,
}

/// One mount of `/proc/self/mountinfo`.
struct Mount {
    device: String,
    root: PathBuf,
    mount_point: PathBuf,
}

fn unescape_mountinfo(field: &str) -> PathBuf {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let digits = std::str::from_utf8(&bytes[index + 1..index + 4]).ok();
            if let Some(value) = digits.and_then(|digits| u8::from_str_radix(digits, 8).ok()) {
                out.push(value);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    PathBuf::from(OsStr::from_bytes(&out))
}

fn read_mounts() -> std::io::Result<Vec<Mount>> {
    let text = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(' ');
            let device = fields.nth(2)?.to_owned();
            let root = unescape_mountinfo(fields.next()?);
            let mount_point = unescape_mountinfo(fields.next()?);
            Some(Mount {
                device,
                root,
                mount_point,
            })
        })
        .collect())
}

/// `path` and the other names it has through other mounts of its filesystem.
fn with_aliases(path: &Path, mounts: &[Mount]) -> Vec<PathBuf> {
    let mut names = vec![path.to_path_buf()];
    let Some(home) = mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.mount_point))
        .max_by_key(|mount| mount.mount_point.as_os_str().len())
    else {
        return names;
    };
    let Ok(inside) = path.strip_prefix(&home.mount_point) else {
        return names;
    };
    let in_filesystem = home.root.join(inside);
    for other in mounts {
        if other.device != home.device {
            continue;
        }
        if let Ok(rest) = in_filesystem.strip_prefix(&other.root) {
            let alias = other.mount_point.join(rest);
            if !names.contains(&alias) {
                names.push(alias);
            }
        }
    }
    names
}

/// Record every file in `tree` that has more than one name, since a second name
/// elsewhere is a way to its content that no path check sees.
fn collect_linked(tree: &Path, into: &mut HashSet<InodeId>) {
    let Ok(metadata) = std::fs::symlink_metadata(tree) else {
        return;
    };
    if metadata.is_dir() {
        if let Ok(entries) = std::fs::read_dir(tree) {
            for entry in entries.flatten() {
                collect_linked(&entry.path(), into);
            }
        }
    } else if metadata.nlink() > 1 && !metadata.file_type().is_symlink() {
        into.insert((metadata.dev(), metadata.ino()));
    }
}

impl Guard {
    /// Build the guard for a configuration.
    ///
    /// `ancestors` are the directories above read-denied paths and `pool_dirs`
    /// the directories the inode pool lives in.
    pub(crate) fn new(
        config: &SandboxConfigData,
        ancestors: HashSet<PathBuf>,
        pool_dirs: Vec<PathBuf>,
    ) -> Result<Self> {
        let mounts = read_mounts().map_err(|error| {
            crate::error::Error::InitFailed(format!("cannot read /proc/self/mountinfo: {error}"))
        })?;
        let mut guard = Self {
            ancestors,
            pool_dirs,
            ipc_socket: config.ipc_socket().map(Path::to_path_buf),
            ..Self::default()
        };

        let named: Vec<PathBuf> = landlock_rules::plan(config)
            .into_iter()
            .filter(|rule| rule.grant)
            .map(|rule| std::fs::canonicalize(&rule.path).unwrap_or(rule.path))
            .collect();
        guard.named = expand(&named, &mounts);
        guard.protected = landlock_rules::protected_patterns(config);

        if let Some(read) = config.read_denylist() {
            let resolved = read.resolve()?;
            guard.reads_denied = true;
            guard.read_trees = expand(&resolved.trees, &mounts);
            guard.read_guarded_parents = resolved.guarded_parents.clone();
            guard.socket_paths = resolved.sockets.clone();
            guard.runtime_dir = resolved.runtime_dir.clone();
            for socket in &guard.socket_paths {
                if let Ok(metadata) = std::fs::metadata(socket) {
                    guard.socket_inodes.insert((metadata.dev(), metadata.ino()));
                }
            }
            // Sockets are denied as connect targets, not as files, and a socket
            // directory such as `/tmp` is no credential store.
            let sockets = resolved.sockets;
            guard.read_trees.retain(|tree| !sockets.contains(tree));
            for tree in &guard.read_trees {
                collect_linked(tree, &mut guard.inodes);
            }
        }

        if let Some(write) = config.write_denylist() {
            let resolved = write.resolve()?;
            guard.writes_denied = true;
            guard.write = WriteRules::new(&resolved, &mounts);
            for tree in &guard.write.trees {
                collect_linked(tree, &mut guard.inodes);
                if let (Some(parent), Some(name)) = (tree.parent(), tree.file_name()) {
                    guard
                        .denied_children
                        .entry(parent.to_path_buf())
                        .or_default()
                        .push(name.as_bytes().to_vec());
                }
            }
        }
        Ok(guard)
    }

    /// Whether any denial is configured, so that opens that only read matter.
    pub(crate) fn watches_reads(&self) -> bool {
        self.reads_denied || !self.protected.is_empty()
    }

    /// Whether `path` is below a credential store that nothing named opens for
    /// it: a path the configuration names, at or inside the store, opens the
    /// part of the store beneath it.
    pub(crate) fn read_denied(&self, path: &Path) -> bool {
        let opened = |names: &dyn Fn(&Path) -> bool| {
            self.named
                .iter()
                .any(|named| path.starts_with(named) && names(named))
        };
        self.read_trees
            .iter()
            .any(|tree| path.starts_with(tree) && !opened(&|named| named.starts_with(tree)))
            || self
                .protected
                .iter()
                .any(|pattern| pattern.matches(path) && !opened(&|named| pattern.matches(named)))
    }

    /// Whether the name `path` may not be created, changed or given to
    /// something else.
    pub(crate) fn write_denied(&self, path: &Path) -> bool {
        if self.pool_dirs.iter().any(|dir| path.starts_with(dir)) {
            return true;
        }
        if !self.writes_denied {
            return false;
        }
        let rules = &self.write;
        rules.trees.iter().any(|tree| path.starts_with(tree))
            || rules
                .patterns
                .iter()
                .any(|pattern| pattern.matches(path) && !rules.exempted(pattern, path))
    }

    /// Whether the name `path` may not be removed or renamed: everything that is
    /// write-denied, the credential stores, and the directories that hold them,
    /// which could otherwise be swapped for a prepared copy.
    pub(crate) fn removal_denied(&self, path: &Path) -> bool {
        if self.write_denied(path) || self.read_denied(path) {
            return true;
        }
        if self.read_guarded_parents.iter().any(|dir| dir == path) {
            return true;
        }
        let rules = &self.write;
        rules.guarded_parents.iter().any(|dir| dir == path)
            || rules
                .pattern_parents
                .iter()
                .any(|pattern| pattern.matches_exactly(path) && !rules.exempted(pattern, path))
    }

    /// Whether `id` is a file with another name in a denied tree.
    pub(crate) fn inode_denied(&self, id: InodeId) -> bool {
        self.inodes.contains(&id)
    }

    /// Whether `path` is a directory above a denied path.
    pub(crate) fn is_ancestor(&self, path: &Path) -> bool {
        self.ancestors.contains(path)
    }

    /// The names directly inside `directory` that are write-denied, which can
    /// resolve to a new entry on a filesystem that folds case.
    pub(crate) fn denied_names(&self, directory: &Path) -> &[Vec<u8>] {
        self.denied_children
            .get(directory)
            .map_or(&[], Vec::as_slice)
    }

    /// Whether a unix socket at `path` (with this identity, when it exists) is
    /// one the sandbox may not connect to.
    pub(crate) fn socket_denied(&self, path: &Path, id: Option<InodeId>) -> bool {
        if !self.reads_denied || self.ipc_socket.as_deref() == Some(path) {
            return false;
        }
        self.socket_paths.iter().any(|socket| socket == path)
            || id.is_some_and(|id| self.socket_inodes.contains(&id))
            || self
                .runtime_dir
                .as_deref()
                .is_some_and(|dir| path.starts_with(dir))
    }

    /// Whether abstract unix sockets are off limits: they have no path to check
    /// and are reachable from every process in the network namespace.
    pub(crate) fn abstract_sockets_denied(&self) -> bool {
        self.reads_denied
    }
}

fn expand(trees: &[PathBuf], mounts: &[Mount]) -> Vec<PathBuf> {
    let mut all = Vec::new();
    for tree in trees {
        for alias in with_aliases(tree, mounts) {
            if !all.contains(&alias) {
                all.push(alias);
            }
        }
    }
    all
}

impl WriteRules {
    fn new(resolved: &Resolved, mounts: &[Mount]) -> Self {
        let mut pattern_parents = Vec::new();
        for pattern in &resolved.patterns {
            for parent in pattern.guarded_parents() {
                if !pattern_parents.contains(&parent) {
                    pattern_parents.push(parent);
                }
            }
        }
        Self {
            trees: expand(&resolved.trees, mounts),
            patterns: resolved.patterns.clone(),
            exempt: resolved.exempt.clone(),
            guarded_parents: resolved.guarded_parents.clone(),
            pattern_parents,
        }
    }

    /// Whether an exemption leaves `path` alone for `pattern`; it narrows only
    /// the patterns that may start anywhere.
    fn exempted(&self, pattern: &Pattern, path: &Path) -> bool {
        pattern.is_anywhere() && self.exempt.iter().any(|dir| path.starts_with(dir))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::platform::unresolved::resolved as grant_path;
    use crate::{ReadDenylist, SandboxConfig, WriteDenylist};

    fn guard(home: &Path) -> Guard {
        let (_, data, _) = SandboxConfig::builder()
            .read_denylist(ReadDenylist::credentials().home(home))
            .write_denylist(WriteDenylist::persistence().home(home))
            .build()
            .into_parts();
        Guard::new(&data, HashSet::new(), Vec::new()).unwrap()
    }

    #[test]
    fn mountinfo_octal_escapes_are_undone() {
        assert_eq!(
            unescape_mountinfo("/mnt/with\\040space"),
            PathBuf::from("/mnt/with space")
        );
        assert_eq!(unescape_mountinfo("/plain"), PathBuf::from("/plain"));
    }

    #[test]
    fn persistence_files_and_repository_hooks_are_write_denied_by_name() {
        let home = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(home.path()).unwrap();
        let guard = guard(&root);
        for denied in [
            ".zshrc",
            ".config/fish/config.fish",
            ".ssh/authorized_keys",
            ".vimrc",
            "work/repo/.git/hooks/pre-commit",
            "work/repo/.git/config",
            "work/repo/.git/modules/x/hooks/post-merge",
            "work/repo/.git/modules/x/y/config",
            ".local/lib/python3.12/site-packages/usercustomize.py",
        ] {
            assert!(guard.write_denied(&root.join(denied)), "{denied}");
        }
        for allowed in [
            "notes.txt",
            ".cache/x",
            "work/repo/src/lib.rs",
            "work/repo/.git/index",
            "work/repo/.git/modules/x/index",
            ".local/lib/python3.12/other",
        ] {
            assert!(!guard.write_denied(&root.join(allowed)), "{allowed}");
        }
    }

    #[test]
    fn the_directories_above_a_denied_name_cannot_be_removed_or_renamed() {
        let home = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(home.path()).unwrap();
        let guard = guard(&root);
        for held in [
            ".config",
            ".cargo",
            "work/repo/.git",
            "work/repo/.git/modules",
            "work/repo/.git/modules/sub",
        ] {
            assert!(guard.removal_denied(&root.join(held)), "{held}");
        }
        assert!(!guard.removal_denied(&root.join("work/repo")));
        assert!(!guard.removal_denied(&root.join("work/repo/.git/modules/sub/objects")));
        assert!(!guard.removal_denied(&root));
    }

    #[test]
    fn credentials_are_denied_for_reading_and_writing() {
        let home = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(home.path()).unwrap();
        let guard = guard(&root);
        assert!(guard.read_denied(&root.join(".aws/credentials")));
        assert!(guard.write_denied(&root.join(".aws/credentials")));
        assert!(!guard.read_denied(&root.join(".zshrc")));
    }

    #[test]
    fn a_path_the_configuration_names_opens_the_part_of_a_store_it_names() {
        let home = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(home.path()).unwrap();
        for relative in [".ssh/keys", ".aws"] {
            std::fs::create_dir_all(root.join(relative)).unwrap();
        }
        let (_, data, _) = SandboxConfig::builder()
            .read_denylist(ReadDenylist::credentials().home(&root))
            .readable(grant_path(&root))
            .readable(grant_path(root.join(".ssh/keys")))
            .build()
            .into_parts();
        let guard = Guard::new(&data, HashSet::new(), Vec::new()).unwrap();

        // A grant of the directory holding the stores opens none of them.
        assert!(guard.read_denied(&root.join(".aws/credentials")));
        assert!(guard.read_denied(&root.join(".ssh/id_ed25519")));
        // A grant inside a store opens what it names and nothing else.
        assert!(!guard.read_denied(&root.join(".ssh/keys/id")));
        assert!(!guard.read_denied(&root.join("notes.txt")));
    }

    #[test]
    fn the_security_toggles_protect_by_name_wherever_a_grant_reaches() {
        let home = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(home.path()).unwrap();
        std::fs::create_dir_all(root.join("project/.ssh")).unwrap();
        let (_, data, _) = SandboxConfig::builder()
            .readable(grant_path(&root))
            .readable(grant_path(root.join("project/.ssh")))
            .build()
            .into_parts();
        let guard = Guard::new(&data, HashSet::new(), Vec::new()).unwrap();

        assert!(guard.watches_reads());
        assert!(guard.read_denied(&root.join(".aws/credentials")));
        assert!(guard.read_denied(&root.join(".npmrc")));
        assert!(!guard.read_denied(&root.join("notes.txt")));
        // The grant naming a store opens it.
        assert!(!guard.read_denied(&root.join("project/.ssh/id")));
        assert!(guard.read_denied(&root.join(".ssh/id")));
    }

    #[test]
    fn a_grant_naming_a_store_opens_it_but_not_a_store_denied_inside_it() {
        let home = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(home.path()).unwrap();
        std::fs::create_dir_all(root.join(".ssh/inner")).unwrap();
        let (_, data, _) = SandboxConfig::builder()
            .read_denylist(
                ReadDenylist::credentials()
                    .home(&root)
                    .deny(root.join(".ssh/inner")),
            )
            .readable(grant_path(root.join(".ssh")))
            .build()
            .into_parts();
        let guard = Guard::new(&data, HashSet::new(), Vec::new()).unwrap();

        assert!(!guard.read_denied(&root.join(".ssh/id_ed25519")));
        assert!(guard.read_denied(&root.join(".ssh/inner/secret")));
    }

    #[test]
    fn an_exemption_leaves_a_private_clones_hooks_alone() {
        let home = tempfile::tempdir().unwrap();
        let clones = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(home.path()).unwrap();
        let clones = std::fs::canonicalize(clones.path()).unwrap();
        let (_, data, _) = SandboxConfig::builder()
            .write_denylist(WriteDenylist::persistence().home(&root).except(&clones))
            .build()
            .into_parts();
        let guard = Guard::new(&data, HashSet::new(), Vec::new()).unwrap();
        assert!(!guard.write_denied(&clones.join("checkout/.git/hooks/sample")));
        assert!(!guard.removal_denied(&clones.join("checkout/.git")));
        assert!(guard.write_denied(&root.join("work/.git/hooks/pre-commit")));
    }

    #[test]
    fn a_file_with_a_second_name_in_a_denied_tree_is_denied_by_inode() {
        let home = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(home.path()).unwrap();
        std::fs::create_dir_all(root.join(".ssh")).unwrap();
        std::fs::write(root.join(".ssh/authorized_keys"), "k").unwrap();
        std::fs::hard_link(root.join(".ssh/authorized_keys"), root.join("elsewhere")).unwrap();
        let metadata = std::fs::metadata(root.join("elsewhere")).unwrap();
        let guard = guard(&root);
        assert!(guard.inode_denied((metadata.dev(), metadata.ino())));
    }
}
