//! Security configuration for sandbox profiles.
//!
//! The sandbox profile is generated once, when the sandbox is created, so
//! protections are expressed as a set of toggles rather than as runtime hooks.
//!
//! # Presets
//!
//! - [`SecurityConfig::strict`] - maximum protection (the default)
//! - [`SecurityConfig::interactive`] - strict, but lets macOS prompt for
//!   TCC-protected folders
//! - [`SecurityConfig::permissive`] - minimal restrictions
//!
//! # Overrides
//!
//! [`SecurityOverrides`] carries a partial set of toggles and can be layered
//! onto any preset, which is how the CLI merges a config file and command-line
//! flags without restating every switch.
//!
//! ```rust,ignore
//! use heel::{SecurityConfig, SecurityOverrides};
//!
//! let mut config = SecurityConfig::strict();
//! config.apply(&SecurityOverrides {
//!     protect_user_home: Some(false),
//!     ..SecurityOverrides::default()
//! });
//! ```

use serde::Deserialize;

/// Define the toggle set once, and derive the configuration, its getters, its
/// builder and its override type from that single list.
///
/// Adding a protection here adds it everywhere it must appear, which is what
/// keeps the CLI, the config file and the profile templates from drifting
/// apart.
macro_rules! security_toggles {
    ($( $(#[$doc:meta])* $name:ident ),* $(,)?) => {
        /// Static security configuration for sandbox profile generation.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct SecurityConfig {
            $( $(#[$doc])* $name: bool, )*
        }

        impl SecurityConfig {
            $(
                $(#[$doc])*
                pub fn $name(&self) -> bool {
                    self.$name
                }
            )*

            /// Layer a partial set of toggles onto this configuration.
            pub fn apply(&mut self, overrides: &SecurityOverrides) {
                $(
                    if let Some(value) = overrides.$name {
                        self.$name = value;
                    }
                )*
            }
        }

        impl SecurityConfigBuilder {
            $(
                $(#[$doc])*
                pub fn $name(mut self, enabled: bool) -> Self {
                    self.config.$name = enabled;
                    self
                }
            )*
        }

        /// A partial set of security toggles to layer onto a preset.
        ///
        /// Every field is `None` by default, meaning "leave the preset alone".
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
        #[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
        pub struct SecurityOverrides {
            $( $(#[$doc])* pub $name: Option<bool>, )*
        }
    };
}

security_toggles! {
    /// Protect user home directories (`/Users`, `/home`).
    protect_user_home,
    /// Let macOS raise TCC prompts for protected folders (Desktop, Documents,
    /// Downloads and friends) instead of denying them in the profile.
    allow_tcc_prompts,
    /// Protect SSH and GPG credentials (`.ssh`, `.gnupg`).
    protect_credentials,
    /// Protect cloud provider configuration (`.aws`, `.kube`, `.docker`).
    protect_cloud_config,
    /// Protect browser data (cookies, history, saved passwords).
    protect_browser_data,
    /// Protect the system keychain.
    protect_keychain,
    /// Protect shell history files.
    protect_shell_history,
    /// Protect package manager credentials (`.npmrc`, `.pypirc`, `.netrc`).
    protect_package_credentials,
    /// Allow GPU access (Metal, CUDA, OpenCL).
    allow_gpu,
    /// Allow NPU / Neural Engine access (CoreML, ANE).
    allow_npu,
    /// Allow general hardware access (USB, Bluetooth, cameras).
    allow_hardware,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self::strict()
    }
}

impl SecurityConfig {
    /// Maximum protection: every data protection on, TCC folders denied without
    /// prompting, GPU and NPU available, general hardware denied.
    pub fn strict() -> Self {
        Self {
            protect_user_home: true,
            allow_tcc_prompts: false,
            protect_credentials: true,
            protect_cloud_config: true,
            protect_browser_data: true,
            protect_keychain: true,
            protect_shell_history: true,
            protect_package_credentials: true,
            allow_gpu: true,
            allow_npu: true,
            allow_hardware: false,
        }
    }

    /// Strict data protection, but TCC-protected folders are left to macOS so
    /// the user can approve them interactively.
    pub fn interactive() -> Self {
        Self {
            allow_tcc_prompts: true,
            ..Self::strict()
        }
    }

    /// Minimal restrictions, for code you already trust.
    pub fn permissive() -> Self {
        Self {
            protect_user_home: false,
            allow_tcc_prompts: true,
            protect_credentials: false,
            protect_cloud_config: false,
            protect_browser_data: false,
            protect_keychain: false,
            protect_shell_history: false,
            protect_package_credentials: false,
            allow_gpu: true,
            allow_npu: true,
            allow_hardware: true,
        }
    }

    /// Start from the strict preset.
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder {
            config: Self::strict(),
        }
    }

    /// Return this configuration with `overrides` layered on top.
    pub fn with(mut self, overrides: &SecurityOverrides) -> Self {
        self.apply(overrides);
        self
    }
}

/// Builder for [`SecurityConfig`].
#[derive(Debug, Clone)]
pub struct SecurityConfigBuilder {
    config: SecurityConfig,
}

impl Default for SecurityConfigBuilder {
    fn default() -> Self {
        SecurityConfig::builder()
    }
}

impl SecurityConfigBuilder {
    /// Start from the permissive preset instead of the strict one.
    pub fn from_permissive() -> Self {
        Self {
            config: SecurityConfig::permissive(),
        }
    }

    /// Start from the interactive preset.
    pub fn from_interactive() -> Self {
        Self {
            config: SecurityConfig::interactive(),
        }
    }

    /// Finish building.
    pub fn build(self) -> SecurityConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_enables_every_protection() {
        let config = SecurityConfig::strict();

        assert!(config.protect_user_home());
        assert!(!config.allow_tcc_prompts());
        assert!(config.protect_credentials());
        assert!(config.protect_cloud_config());
        assert!(config.protect_browser_data());
        assert!(config.protect_keychain());
        assert!(config.protect_shell_history());
        assert!(config.protect_package_credentials());
        assert!(config.allow_gpu());
        assert!(config.allow_npu());
        assert!(!config.allow_hardware());
    }

    #[test]
    fn permissive_disables_data_protections() {
        let config = SecurityConfig::permissive();

        assert!(!config.protect_user_home());
        assert!(config.allow_tcc_prompts());
        assert!(!config.protect_credentials());
        assert!(!config.protect_keychain());
        assert!(config.allow_hardware());
    }

    #[test]
    fn interactive_differs_from_strict_only_in_tcc_prompts() {
        let interactive = SecurityConfig::interactive();
        let strict = SecurityConfig::strict();

        assert!(interactive.allow_tcc_prompts());
        assert!(!strict.allow_tcc_prompts());
        assert_eq!(
            SecurityConfig {
                allow_tcc_prompts: false,
                ..interactive
            },
            strict
        );
    }

    #[test]
    fn overrides_only_touch_the_fields_they_set() {
        let mut config = SecurityConfig::strict();
        config.apply(&SecurityOverrides {
            protect_user_home: Some(false),
            allow_hardware: Some(true),
            ..SecurityOverrides::default()
        });

        assert!(!config.protect_user_home());
        assert!(config.allow_hardware());
        // Untouched fields keep their preset value.
        assert!(config.protect_credentials());
    }

    #[test]
    fn empty_overrides_are_a_no_op() {
        let config = SecurityConfig::strict();
        assert_eq!(
            config.clone().with(&SecurityOverrides::default()),
            config,
            "an empty override set must not change anything"
        );
    }

    #[test]
    fn overrides_parse_from_partial_config_files() {
        let overrides: SecurityOverrides =
            toml::from_str("protect-user-home = false\nallow-gpu = true").expect("parses");
        assert_eq!(overrides.protect_user_home, Some(false));
        assert_eq!(overrides.allow_gpu, Some(true));
        assert_eq!(overrides.protect_keychain, None);
    }

    #[test]
    fn builder_starts_from_the_requested_preset() {
        let config = SecurityConfigBuilder::from_permissive()
            .protect_credentials(true)
            .build();

        assert!(config.protect_credentials());
        assert!(!config.protect_user_home());
    }
}
