//! What a sandboxed process may do with a configured path.
//!
//! A sandbox is configured with a list of [`Grant`]s rather than one list per
//! operation. The rules that decide what a backend emits — write implies read,
//! execute implies read, a writable path is denied execute unless the grant
//! also allows it — are then properties of a single [`Access`] value that every
//! backend reads the same way, instead of a cross-product of three lists that
//! each backend has to rediscover.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;
use serde::de::{Deserializer, Visitor};

/// The operations a [`Grant`] permits.
///
/// [`Access::WRITE`] and [`Access::EXEC`] include read by construction. No
/// backend can express a path that is writable or executable but not readable —
/// opening a file to write it and mapping it to run it are both reads — so this
/// type does not offer that shape either.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Access(u8);

impl Access {
    const READ_BIT: u8 = 1 << 0;
    const WRITE_BIT: u8 = 1 << 1;
    const EXEC_BIT: u8 = 1 << 2;

    /// Read the path, and list it when it is a directory.
    pub const READ: Self = Self(Self::READ_BIT);

    /// Read and write the path, including creating and removing entries under
    /// a directory. A path with this access and not [`Access::EXEC`] is denied
    /// execute, which is what stops a sandboxed process from writing a payload
    /// and running it.
    pub const WRITE: Self = Self(Self::READ_BIT | Self::WRITE_BIT);

    /// Read and execute the path. A directory grants execute to everything
    /// beneath it; a file grants it to that file.
    pub const EXEC: Self = Self(Self::READ_BIT | Self::EXEC_BIT);

    /// Everything both grants.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether the path may be written.
    #[must_use]
    pub const fn can_write(self) -> bool {
        self.0 & Self::WRITE_BIT != 0
    }

    /// Whether the path may be executed.
    #[must_use]
    pub const fn can_execute(self) -> bool {
        self.0 & Self::EXEC_BIT != 0
    }
}

impl std::ops::BitOr for Access {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

impl std::ops::BitOrAssign for Access {
    fn bitor_assign(&mut self, other: Self) {
        *self = self.union(other);
    }
}

impl fmt::Display for Access {
    /// The mode string [`Access::from_str`] accepts, such as `rwx`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("r")?;
        if self.can_write() {
            f.write_str("w")?;
        }
        if self.can_execute() {
            f.write_str("x")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Access {
    /// Shows the mode string, which is what a failing assertion needs to read.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Access({self})")
    }
}

/// Why a mode string is not an [`Access`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseAccessError {
    /// The string was empty.
    #[error("empty access mode: expected `r`, `rw`, `rx` or `rwx`")]
    Empty,

    /// The string contained something other than `r`, `w` or `x`.
    #[error("unknown access mode letter `{0}`: expected `r`, `w` or `x`")]
    UnknownLetter(char),

    /// The same letter appeared twice.
    #[error("access mode letter `{0}` is repeated")]
    RepeatedLetter(char),

    /// Write and execute include read, so a mode that omits `r` is a mistake
    /// rather than a narrower grant.
    #[error("access mode `{0}` does not grant read; write it as `r{0}`")]
    MissingRead(String),
}

impl FromStr for Access {
    type Err = ParseAccessError;

    /// Parse a mode string: some of `r`, `w` and `x`, each at most once, and
    /// always including `r`.
    fn from_str(mode: &str) -> Result<Self, Self::Err> {
        if mode.is_empty() {
            return Err(ParseAccessError::Empty);
        }

        let mut bits = 0u8;
        for letter in mode.chars() {
            let bit = match letter {
                'r' => Self::READ_BIT,
                'w' => Self::WRITE_BIT,
                'x' => Self::EXEC_BIT,
                other => return Err(ParseAccessError::UnknownLetter(other)),
            };
            if bits & bit != 0 {
                return Err(ParseAccessError::RepeatedLetter(letter));
            }
            bits |= bit;
        }

        if bits & Self::READ_BIT == 0 {
            return Err(ParseAccessError::MissingRead(mode.to_owned()));
        }

        Ok(Self(bits))
    }
}

impl<'de> Deserialize<'de> for Access {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ModeVisitor;

        impl Visitor<'_> for ModeVisitor {
            type Value = Access;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an access mode such as \"r\", \"rw\", \"rx\" or \"rwx\"")
            }

            fn visit_str<E: serde::de::Error>(self, mode: &str) -> Result<Access, E> {
                mode.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ModeVisitor)
    }
}

/// One configured path and what the sandbox may do with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    path: PathBuf,
    access: Access,
}

impl Grant {
    /// Grant `access` on `path`.
    pub fn new(path: impl AsRef<Path>, access: Access) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            access,
        }
    }

    /// The path this grant covers.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What the sandbox may do with it.
    #[must_use]
    pub fn access(&self) -> Access {
        self.access
    }

    /// Add `access` to what this grant already permits.
    pub(crate) fn widen(&mut self, access: Access) {
        self.access |= access;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_exec_include_read() {
        // The backends cannot express write-without-read or exec-without-read,
        // so neither can the type: a caller cannot build one by mistake.
        for access in [Access::READ, Access::WRITE, Access::EXEC] {
            assert_eq!(access.to_string().chars().next(), Some('r'), "{access:?}");
        }
        assert!(!Access::READ.can_write());
        assert!(!Access::READ.can_execute());
        assert!(Access::WRITE.can_write());
        assert!(!Access::WRITE.can_execute());
        assert!(Access::EXEC.can_execute());
        assert!(!Access::EXEC.can_write());
    }

    #[test]
    fn union_keeps_both_sides() {
        let both = Access::WRITE | Access::EXEC;
        assert!(both.can_write());
        assert!(both.can_execute());
        assert_eq!(both, Access::EXEC.union(Access::WRITE));
        assert_eq!(both.to_string(), "rwx");

        let mut widened = Access::READ;
        widened |= Access::EXEC;
        assert_eq!(widened, Access::EXEC);
    }

    #[test]
    fn modes_round_trip_through_their_string_form() {
        for access in [
            Access::READ,
            Access::WRITE,
            Access::EXEC,
            Access::WRITE | Access::EXEC,
        ] {
            let mode = access.to_string();
            assert_eq!(mode.parse::<Access>().expect(&mode), access);
        }
        assert_eq!(
            "rwx".parse::<Access>().unwrap(),
            Access::WRITE | Access::EXEC
        );
        assert_eq!("xr".parse::<Access>().unwrap(), Access::EXEC);
    }

    #[test]
    fn modes_without_read_are_rejected_rather_than_narrowed() {
        assert_eq!(
            "w".parse::<Access>().unwrap_err(),
            ParseAccessError::MissingRead("w".to_owned())
        );
        assert_eq!(
            "x".parse::<Access>().unwrap_err(),
            ParseAccessError::MissingRead("x".to_owned())
        );
    }

    #[test]
    fn malformed_modes_are_rejected() {
        assert_eq!("".parse::<Access>().unwrap_err(), ParseAccessError::Empty);
        assert_eq!(
            "rz".parse::<Access>().unwrap_err(),
            ParseAccessError::UnknownLetter('z')
        );
        assert_eq!(
            "rww".parse::<Access>().unwrap_err(),
            ParseAccessError::RepeatedLetter('w')
        );
        assert_eq!(
            "RW".parse::<Access>().unwrap_err(),
            ParseAccessError::UnknownLetter('R')
        );
    }

    #[test]
    fn a_grant_widens_to_the_union() {
        let mut grant = Grant::new("/opt/tools", Access::WRITE);
        grant.widen(Access::EXEC);

        assert_eq!(grant.path(), Path::new("/opt/tools"));
        assert_eq!(grant.access(), Access::WRITE | Access::EXEC);
    }
}
