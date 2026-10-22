//! Stable identities for sandboxes whose path grants outlive one sandbox.

use crate::error::{Error, Result};
use crate::grant::Grant;

/// A stable identity for sandboxes that share persistent path grants.
///
/// On Windows, the name selects the `heel-id-<name>` AppContainer profile.
/// Persistent grants are written for its package SID and remain until
/// [`Identity::remove`]; ordinary grants use a distinct capability SID for
/// each sandbox. On macOS and Linux, persistent grants become ordinary
/// sandbox policy grants, while [`Identity::prepare`] and
/// [`Identity::remove`] do nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    name: String,
    persistent: Vec<Grant>,
}

impl Identity {
    /// Use `name` to identify sandboxes that share persistent path grants.
    ///
    /// The name must be non-empty, contain only ASCII letters, digits, spaces,
    /// hyphens, underscores, and periods, and fit in a 64-character
    /// `heel-id-<name>` profile name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidProfile`] if the name does not meet these
    /// requirements.
    pub fn named(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let profile_name = format!("heel-id-{name}");
        if name.is_empty()
            || name.chars().any(|character| {
                !character.is_ascii_alphanumeric() && !matches!(character, '-' | '_' | '.' | ' ')
            })
            || profile_name.len() > 64
        {
            return Err(Error::InvalidProfile(format!(
                "identity {:?} must be non-empty, contain only ASCII letters, digits, spaces, hyphens, underscores or periods, and fit in a 64-character AppContainer profile name including the `heel-id-` prefix",
                name
            )));
        }
        Ok(Self {
            name,
            persistent: Vec::new(),
        })
    }

    /// Keep `grant` on the identity's AppContainer profile.
    #[must_use]
    pub fn persistent_grant(mut self, grant: Grant) -> Self {
        match self
            .persistent
            .iter_mut()
            .find(|existing| existing.path() == grant.path())
        {
            Some(existing) => existing.widen(grant.access()),
            None => self.persistent.push(grant),
        }
        self
    }

    /// The name used to construct this identity.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The paths retained for this identity.
    pub fn persistent_grants(&self) -> &[Grant] {
        &self.persistent
    }

    /// Prepare this identity's persistent grants.
    ///
    /// On Windows, this creates or opens the named profile and applies its
    /// persistent grants. On macOS and Linux, it does nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InitFailed`] if Windows cannot prepare the profile or
    /// grants.
    pub fn prepare(&self) -> Result<()> {
        #[cfg(windows)]
        crate::platform::windows::identity::prepare(self).map_err(|source| {
            Error::InitFailed(format!(
                "cannot prepare identity {}: {}",
                self.name,
                crate::platform::windows::with_causes(&source)
            ))
        })?;

        Ok(())
    }

    /// Remove this identity's persistent grants and profile.
    ///
    /// On Windows, this revokes the package SID's grants and deletes the named
    /// profile. On macOS and Linux, it does nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InitFailed`] if Windows cannot remove the grants or
    /// profile.
    pub fn remove(&self) -> Result<()> {
        #[cfg(windows)]
        crate::platform::windows::identity::remove(self).map_err(|source| {
            Error::InitFailed(format!(
                "cannot remove identity {}: {}",
                self.name,
                crate::platform::windows::with_causes(&source)
            ))
        })?;

        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn profile_name(&self) -> String {
        format!("heel-id-{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::Access;

    #[test]
    fn validates_names_for_appcontainer_profiles() {
        assert!(Identity::named("toolchain-1.98").is_ok());
        assert!(Identity::named("x".repeat(56)).is_ok());

        for name in ["", "a/b", &"x".repeat(57)] {
            let Err(Error::InvalidProfile(message)) = Identity::named(name) else {
                panic!("identity name {name:?} must be rejected with its validation rule");
            };
            assert!(
                message.contains(&format!("{name:?}")),
                "identity name missing from {message:?}"
            );
            assert!(
                message.contains("non-empty") && message.contains("ASCII"),
                "validation rule missing from {message:?}"
            );
            assert!(
                message.contains("64-character"),
                "profile-name limit missing from {message:?}"
            );
        }
    }

    #[test]
    fn persistent_grants_union_access_for_the_same_path() {
        let directory = std::env::temp_dir();
        let identity = Identity::named("build")
            .expect("the identity name is valid")
            .persistent_grant(Grant::new(&directory, Access::READ))
            .persistent_grant(Grant::new(&directory, Access::EXEC));

        assert_eq!(
            identity.persistent_grants(),
            [Grant::new(directory, Access::READ | Access::EXEC)]
        );
    }
}
