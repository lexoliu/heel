//! Working directory management for the sandbox.
//!
//! The sandbox operates within a dedicated working directory it may freely read
//! and write. By default the directory is generated under the system temporary
//! directory from four English words plus a random suffix, and it is removed
//! when the sandbox is dropped.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Word list for generating readable directory names.
const WORDS: &[&str] = &[
    "apple", "banana", "cherry", "dragon", "eagle", "falcon", "garden", "harbor", "island",
    "jungle", "kitten", "lemon", "mango", "night", "ocean", "planet", "queen", "river", "silver",
    "tiger", "umbrella", "violet", "winter", "yellow", "zebra", "anchor", "bridge", "castle",
    "desert", "ember", "forest", "glacier", "horizon", "ivory", "jasmine", "kingdom", "lantern",
    "meadow", "nebula", "orchid", "phoenix", "quartz", "rainbow", "shadow", "thunder", "urban",
    "velvet", "whisper", "crystal", "dolphin", "eclipse", "firefly", "lexo", "granite", "hollow",
    "indigo", "journey", "karma", "lotus", "marble", "nomad", "oasis", "prism", "quest", "ripple",
    "sphinx", "temple", "unity", "vortex", "willow", "xenon", "yonder", "zenith", "amber",
    "blazer", "copper", "dusk", "ether", "flame", "golden", "haze", "iron", "jade", "kindle",
    "lunar", "mystic", "nova", "onyx", "pearl", "radiant", "storm", "tidal", "ultra", "vivid",
    "wave", "azure", "breeze",
];

/// Generate a directory name of four words and a random suffix.
///
/// The suffix makes collisions between concurrent sandboxes effectively
/// impossible, which is what lets configuration building stay free of I/O.
pub(crate) fn generate_working_dir_name() -> String {
    use rand::Rng;
    use rand::seq::SliceRandom;

    let mut rng = rand::thread_rng();
    let words: Vec<&str> = WORDS.choose_multiple(&mut rng, 4).copied().collect();
    let suffix: u32 = rng.r#gen();

    format!("heel-{}-{suffix:08x}", words.join("-"))
}

/// Generate a short directory name for an IPC socket.
///
/// Unix socket paths are limited to about a hundred bytes, so this stays terse
/// where the working directory name can afford to be readable.
pub(crate) fn generate_socket_dir_name() -> String {
    use rand::Rng;

    format!("heel-{:08x}", rand::thread_rng().r#gen::<u32>())
}

/// A sandbox working directory that cleans itself up when dropped.
#[derive(Debug)]
pub struct WorkingDir {
    path: PathBuf,
    remove_on_drop: bool,
}

impl WorkingDir {
    /// Create the working directory and canonicalize its path.
    ///
    /// Canonicalization is required, not cosmetic: macOS sandbox profiles match
    /// against resolved paths, so a rule naming `/tmp/x` never matches the
    /// kernel's `/private/tmp/x`.
    ///
    /// `auto` marks a generated directory, which is removed on drop and must
    /// not already exist. A caller-supplied directory is created if missing and
    /// always preserved.
    pub(crate) fn create(path: &Path, auto: bool) -> Result<Self> {
        if auto {
            std::fs::create_dir_all(path).map_err(|error| Error::WorkingDir {
                path: path.to_path_buf(),
                source: error,
            })?;
            // A directory the sandbox created for itself holds the sandboxed
            // process's files and, for IPC, its socket. Neither is anyone
            // else's business, and a shared temp root is world-readable by
            // default.
            restrict_to_owner(path)?;
        } else if !path.exists() {
            std::fs::create_dir_all(path).map_err(|error| Error::WorkingDir {
                path: path.to_path_buf(),
                source: error,
            })?;
            tracing::debug!(path = %path.display(), "created working directory");
        }

        // `dunce` avoids the `\\?\` verbatim prefix that `std` returns on
        // Windows, which many Win32 APIs and child processes do not accept.
        let canonical = dunce::canonicalize(path).map_err(|error| Error::WorkingDir {
            path: path.to_path_buf(),
            source: error,
        })?;

        tracing::debug!(path = %canonical.display(), auto, "working directory ready");

        Ok(Self {
            path: canonical,
            remove_on_drop: auto,
        })
    }

    /// Create a working directory with a generated name inside `parent`.
    ///
    /// For hosts that manage their own sandbox roots rather than letting the
    /// configuration pick one. The generated name carries a random suffix, so
    /// this needs no collision retry, and the directory is removed when the
    /// returned value is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created, restricted to its
    /// owner, or canonicalized.
    pub fn random_in(parent: impl AsRef<Path>) -> Result<Self> {
        Self::create(&parent.as_ref().join(generate_working_dir_name()), true)
    }

    /// The canonical path of the working directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Preserve the directory instead of removing it when the sandbox drops.
    pub(crate) fn keep(&mut self) {
        self.remove_on_drop = false;
    }
}

/// Restrict a directory to its owner.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|error| {
        Error::WorkingDir {
            path: path.to_path_buf(),
            source: error,
        }
    })
}

/// Restrict a directory to its owner.
#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) -> Result<()> {
    Ok(())
}

impl AsRef<Path> for WorkingDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for WorkingDir {
    fn drop(&mut self) {
        if !self.remove_on_drop {
            tracing::debug!(path = %self.path.display(), "keeping working directory");
            return;
        }

        match remove_dir_all::remove_dir_all(&self.path) {
            Ok(()) => tracing::debug!(path = %self.path.display(), "removed working directory"),
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                %error,
                "failed to remove working directory"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_names_use_four_words_and_a_suffix() {
        let name = generate_working_dir_name();
        let rest = name.strip_prefix("heel-").expect("names are prefixed");
        let parts: Vec<&str> = rest.split('-').collect();
        assert_eq!(parts.len(), 5, "four words plus a suffix: {name}");
        for word in &parts[..4] {
            assert!(WORDS.contains(word), "unexpected word {word} in {name}");
        }
        assert_eq!(parts[4].len(), 8, "suffix is eight hex digits: {name}");
    }

    #[test]
    fn socket_directory_names_are_short_and_unique() {
        let name = generate_socket_dir_name();
        assert!(name.len() <= 13, "{name} is too long for a socket path");

        let mut names = std::collections::HashSet::new();
        for _ in 0..1000 {
            names.insert(generate_socket_dir_name());
        }
        assert!(names.len() > 990, "too many collisions");
    }

    #[test]
    fn generated_names_do_not_collide() {
        let mut names = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(
                names.insert(generate_working_dir_name()),
                "generated a duplicate name"
            );
        }
    }

    #[test]
    fn auto_directories_are_removed_on_drop() {
        let path = std::env::temp_dir().join(generate_working_dir_name());
        let dir = WorkingDir::create(&path, true).expect("creates");
        let canonical = dir.path().to_path_buf();
        assert!(canonical.exists());
        drop(dir);
        assert!(!canonical.exists());
    }

    #[test]
    fn kept_directories_survive_drop() {
        let path = std::env::temp_dir().join(generate_working_dir_name());
        let mut dir = WorkingDir::create(&path, true).expect("creates");
        dir.keep();
        let canonical = dir.path().to_path_buf();
        drop(dir);
        assert!(canonical.exists());
        std::fs::remove_dir_all(&canonical).ok();
    }

    #[test]
    fn supplied_directories_are_preserved() {
        let path = std::env::temp_dir().join(generate_working_dir_name());
        std::fs::create_dir_all(&path).expect("creates");
        let dir = WorkingDir::create(&path, false).expect("opens");
        let canonical = dir.path().to_path_buf();
        drop(dir);
        assert!(canonical.exists());
        std::fs::remove_dir_all(&canonical).ok();
    }

    #[cfg(unix)]
    #[test]
    fn generated_directories_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(generate_working_dir_name());
        let dir = WorkingDir::create(&path, true).expect("creates");
        let mode = std::fs::metadata(dir.path())
            .expect("exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "a generated directory must be private");
    }

    #[test]
    fn paths_are_canonicalized() {
        // The system temp dir is a symlink on macOS; a profile built from the
        // unresolved path would silently match nothing.
        let path = std::env::temp_dir().join(generate_working_dir_name());
        let dir = WorkingDir::create(&path, true).expect("creates");
        // Compared against the same canonicalization the type uses: on Windows
        // `std::fs::canonicalize` adds the `\\?\` verbatim prefix that this
        // deliberately avoids, so the two do not agree there.
        assert_eq!(
            dir.path(),
            dunce::canonicalize(dir.path()).expect("already canonical")
        );
    }
}
