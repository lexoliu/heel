//! Stable identities for sandboxes whose path grants outlive one sandbox.

use crate::error::{Error, Result};
use crate::grant::Grant;

/// A stable identity for sandboxes that share persistent path grants.
///
/// On Windows, the name selects two AppContainer profiles, and so two package
/// SIDs: `heel-id-<name>` for sandboxes whose network policy runs the filtering
/// proxy, and `heel-no-<name>` for deny-all sandboxes. A proxied sandbox's
/// package SID receives a machine-wide loopback exemption that persists until
/// [`Identity::remove`]; a deny-all sandbox never runs under that SID, so it
/// cannot inherit the exemption and reach listeners on the host. Persistent
/// grants are written for both package SIDs and remain until
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
    ///
    /// The grant's path is absolute and already resolved, as for any grant.
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
    /// grants, and [`Error::GrantRedirected`] if a persistent grant, or a
    /// directory above one, has become a symbolic link or junction.
    pub fn prepare(&self) -> Result<()> {
        #[cfg(windows)]
        crate::platform::windows::identity::prepare(self).map_err(|source| match source {
            crate::platform::windows::Win32Failure::Internal(
                error @ Error::GrantRedirected { .. },
            ) => error,
            source => Error::InitFailed(format!(
                "cannot prepare identity {}: {}",
                self.name,
                crate::platform::windows::with_causes(&source)
            )),
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

    /// The AppContainer profile `kind` of sandbox runs under.
    #[cfg(windows)]
    pub(crate) fn profile_name(&self, kind: NamedProfile) -> String {
        format!("{}{}", kind.prefix(), self.name)
    }
}

/// Which of an identity's two AppContainer profiles a sandbox runs under.
///
/// The prefixes have the same length and differ in their last letters, so no
/// identity name can make one kind's profile name equal the other's, and a name
/// valid for one is valid for both.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NamedProfile {
    /// The network policy runs the filtering proxy, so the package SID is
    /// exempt from the loopback restriction.
    Proxied,
    /// The network policy denies everything, so the package SID is never
    /// exempt from the loopback restriction.
    DenyAll,
}

#[cfg(windows)]
impl NamedProfile {
    /// Both kinds.
    pub(crate) const ALL: [Self; 2] = [Self::Proxied, Self::DenyAll];

    /// The kind a sandbox runs under, given whether it runs the proxy.
    pub(crate) const fn for_proxy(proxied: bool) -> Self {
        if proxied {
            Self::Proxied
        } else {
            Self::DenyAll
        }
    }

    const fn prefix(self) -> &'static str {
        match self {
            Self::Proxied => "heel-id-",
            Self::DenyAll => "heel-no-",
        }
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
