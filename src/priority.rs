//! Scheduling priority for sandboxed processes.
//!
//! A sandbox may only lower the priority of what it runs. That is what the
//! types here express: there is no value that raises a process above the
//! default, so a host that runs heavy commands next to latency-sensitive work
//! can keep them out of the way without being able to do the opposite.
//!
//! The priority is applied to the sandboxed process itself, so everything it
//! spawns inherits it.

use std::fmt;

/// The lowest nice value a sandbox may ask for.
///
/// Zero is the default priority and negative values raise it, so neither is a
/// nice level a sandbox can express.
const MIN_NICE: u8 = 1;

/// The highest nice value the kernel accepts.
const MAX_NICE: u8 = 19;

/// A nice value a sandbox may apply: `1..=19`, where larger is lower priority.
///
/// The range is part of the type, so a backend never has to check it: a value
/// that exists is a value the kernel will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NiceLevel(u8);

impl NiceLevel {
    /// The gentlest reduction, one step below the default priority.
    pub const LOWEST: Self = Self(MIN_NICE);

    /// The largest reduction the kernel accepts.
    pub const HIGHEST: Self = Self(MAX_NICE);

    /// Create a nice level.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNiceLevel`] when `level` is outside `1..=19`.
    pub const fn new(level: u8) -> Result<Self, InvalidNiceLevel> {
        if level < MIN_NICE || level > MAX_NICE {
            return Err(InvalidNiceLevel { level });
        }
        Ok(Self(level))
    }

    /// The nice value, as the kernel takes it.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for NiceLevel {
    type Error = InvalidNiceLevel;

    fn try_from(level: u8) -> Result<Self, Self::Error> {
        Self::new(level)
    }
}

impl fmt::Display for NiceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Why a number is not a [`NiceLevel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "nice level {level} is out of range: a sandbox may only lower priority, \
     so the level must be between 1 and 19"
)]
pub struct InvalidNiceLevel {
    /// The rejected value.
    pub level: u8,
}

/// How much CPU time a sandboxed process competes for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CpuPriority {
    /// The priority the process would have had anyway.
    #[default]
    Normal,

    /// Run at a lower priority than everything at the default.
    Nice(NiceLevel),
}

/// How much disk bandwidth a sandboxed process competes for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IoPriority {
    /// The I/O priority the process would have had anyway.
    #[default]
    Normal,

    /// Yield to interactive work, without being throttled outright.
    Utility,

    /// Only use bandwidth nothing else wants.
    Background,
}

/// The scheduling priority of a sandboxed process and its descendants.
///
/// The default leaves both the CPU and the I/O priority untouched, which is
/// also what keeps the faster `posix_spawn` path available when no other
/// setting needs a hook between fork and exec.
///
/// ```
/// use heel::{CpuPriority, IoPriority, NiceLevel, ProcessPriority};
///
/// let priority = ProcessPriority::new(
///     CpuPriority::Nice(NiceLevel::new(10)?),
///     IoPriority::Background,
/// );
/// assert!(!priority.is_normal());
/// assert!(ProcessPriority::default().is_normal());
/// # Ok::<(), heel::InvalidNiceLevel>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ProcessPriority {
    cpu: CpuPriority,
    io: IoPriority,
}

impl ProcessPriority {
    /// Lower the CPU and the I/O priority together.
    #[must_use]
    pub const fn new(cpu: CpuPriority, io: IoPriority) -> Self {
        Self { cpu, io }
    }

    /// How much CPU time the process competes for.
    #[must_use]
    pub const fn cpu(self) -> CpuPriority {
        self.cpu
    }

    /// How much disk bandwidth the process competes for.
    #[must_use]
    pub const fn io(self) -> IoPriority {
        self.io
    }

    /// Whether nothing is lowered, so there is nothing for a backend to apply.
    #[must_use]
    pub const fn is_normal(self) -> bool {
        matches!(self.cpu, CpuPriority::Normal) && matches!(self.io, IoPriority::Normal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_whole_accepted_range_builds() {
        for level in MIN_NICE..=MAX_NICE {
            assert_eq!(NiceLevel::new(level).unwrap().get(), level);
        }
        assert_eq!(NiceLevel::LOWEST.get(), MIN_NICE);
        assert_eq!(NiceLevel::HIGHEST.get(), MAX_NICE);
    }

    #[test]
    fn levels_outside_the_range_are_rejected() {
        // Zero is the default priority and 20 is past what the kernel takes;
        // both are mistakes rather than requests to be clamped.
        assert_eq!(
            NiceLevel::new(0).unwrap_err(),
            InvalidNiceLevel { level: 0 }
        );
        assert_eq!(
            NiceLevel::try_from(20).unwrap_err(),
            InvalidNiceLevel { level: 20 }
        );
        assert!(
            NiceLevel::new(0)
                .unwrap_err()
                .to_string()
                .contains("between 1 and 19")
        );
    }

    #[test]
    fn the_default_priority_lowers_nothing() {
        let priority = ProcessPriority::default();
        assert_eq!(priority.cpu(), CpuPriority::Normal);
        assert_eq!(priority.io(), IoPriority::Normal);
        assert!(priority.is_normal());
    }

    #[test]
    fn lowering_either_half_is_not_normal() {
        assert!(
            !ProcessPriority::new(CpuPriority::Nice(NiceLevel::LOWEST), IoPriority::Normal)
                .is_normal()
        );
        assert!(!ProcessPriority::new(CpuPriority::Normal, IoPriority::Utility).is_normal());
    }
}
