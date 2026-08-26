//! Security toggles exposed to JavaScript.

use heel::{SecurityConfig, SecurityOverrides};
use napi_derive::napi;

/// A partial set of security toggles, layered onto the strict preset.
///
/// Every field is optional: omitting one keeps the preset's value.
#[napi(object)]
#[derive(Clone, Default)]
pub struct SecurityConfigJs {
    /// Protect user home directories.
    pub protect_user_home: Option<bool>,
    /// Let macOS prompt for TCC-protected folders instead of denying them.
    pub allow_tcc_prompts: Option<bool>,
    /// Protect SSH and GPG credentials.
    pub protect_credentials: Option<bool>,
    /// Protect cloud provider configuration.
    pub protect_cloud_config: Option<bool>,
    /// Protect browser data.
    pub protect_browser_data: Option<bool>,
    /// Protect the system keychain.
    pub protect_keychain: Option<bool>,
    /// Protect shell history.
    pub protect_shell_history: Option<bool>,
    /// Protect package manager credentials.
    pub protect_package_credentials: Option<bool>,
    /// Allow GPU access.
    pub allow_gpu: Option<bool>,
    /// Allow NPU / Neural Engine access.
    pub allow_npu: Option<bool>,
    /// Allow general hardware access.
    pub allow_hardware: Option<bool>,
}

impl SecurityConfigJs {
    /// The overrides these fields describe.
    fn overrides(&self) -> SecurityOverrides {
        SecurityOverrides {
            protect_user_home: self.protect_user_home,
            allow_tcc_prompts: self.allow_tcc_prompts,
            protect_credentials: self.protect_credentials,
            protect_cloud_config: self.protect_cloud_config,
            protect_browser_data: self.protect_browser_data,
            protect_keychain: self.protect_keychain,
            protect_shell_history: self.protect_shell_history,
            protect_package_credentials: self.protect_package_credentials,
            allow_gpu: self.allow_gpu,
            allow_npu: self.allow_npu,
            allow_hardware: self.allow_hardware,
        }
    }

    /// Apply these toggles to `preset`.
    pub fn apply_to(&self, preset: SecurityConfig) -> SecurityConfig {
        preset.with(&self.overrides())
    }
}

impl From<&SecurityConfig> for SecurityConfigJs {
    fn from(config: &SecurityConfig) -> Self {
        Self {
            protect_user_home: Some(config.protect_user_home()),
            allow_tcc_prompts: Some(config.allow_tcc_prompts()),
            protect_credentials: Some(config.protect_credentials()),
            protect_cloud_config: Some(config.protect_cloud_config()),
            protect_browser_data: Some(config.protect_browser_data()),
            protect_keychain: Some(config.protect_keychain()),
            protect_shell_history: Some(config.protect_shell_history()),
            protect_package_credentials: Some(config.protect_package_credentials()),
            allow_gpu: Some(config.allow_gpu()),
            allow_npu: Some(config.allow_npu()),
            allow_hardware: Some(config.allow_hardware()),
        }
    }
}

/// The strict security preset, with every protection enabled.
#[napi]
pub fn security_config_strict() -> SecurityConfigJs {
    SecurityConfigJs::from(&SecurityConfig::strict())
}

/// The interactive preset: strict, but macOS may prompt for protected folders.
#[napi]
pub fn security_config_interactive() -> SecurityConfigJs {
    SecurityConfigJs::from(&SecurityConfig::interactive())
}

/// The permissive security preset.
#[napi]
pub fn security_config_permissive() -> SecurityConfigJs {
    SecurityConfigJs::from(&SecurityConfig::permissive())
}
