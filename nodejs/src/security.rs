use napi_derive::napi;

/// Security configuration for the sandbox
#[napi(object)]
#[derive(Clone, Default)]
pub struct SecurityConfigJs {
    /// Protect user home directories (/Users, /home)
    pub protect_user_home: Option<bool>,
    /// Protect SSH/GPG credentials (.ssh, .gnupg)
    pub protect_credentials: Option<bool>,
    /// Protect cloud provider config (.aws, .kube, .docker)
    pub protect_cloud_config: Option<bool>,
    /// Protect browser data (cookies, history, passwords)
    pub protect_browser_data: Option<bool>,
    /// Protect system keychain
    pub protect_keychain: Option<bool>,
    /// Protect shell history (.bash_history, .zsh_history, etc.)
    pub protect_shell_history: Option<bool>,
    /// Protect package manager credentials (.npmrc, .pypirc, .netrc)
    pub protect_package_credentials: Option<bool>,
    /// Allow GPU access (Metal, CUDA, OpenCL)
    pub allow_gpu: Option<bool>,
    /// Allow NPU/Neural Engine access (CoreML, ANE)
    pub allow_npu: Option<bool>,
    /// Allow general hardware access (USB, Bluetooth, cameras)
    pub allow_hardware: Option<bool>,
}

impl SecurityConfigJs {
    /// Convert to Rust SecurityConfig, starting from strict preset
    pub fn into_rust(self) -> heel::SecurityConfig {
        let mut builder = heel::SecurityConfig::builder();

        if let Some(v) = self.protect_user_home {
            builder = builder.protect_user_home(v);
        }
        if let Some(v) = self.protect_credentials {
            builder = builder.protect_credentials(v);
        }
        if let Some(v) = self.protect_cloud_config {
            builder = builder.protect_cloud_config(v);
        }
        if let Some(v) = self.protect_browser_data {
            builder = builder.protect_browser_data(v);
        }
        if let Some(v) = self.protect_keychain {
            builder = builder.protect_keychain(v);
        }
        if let Some(v) = self.protect_shell_history {
            builder = builder.protect_shell_history(v);
        }
        if let Some(v) = self.protect_package_credentials {
            builder = builder.protect_package_credentials(v);
        }
        if let Some(v) = self.allow_gpu {
            builder = builder.allow_gpu(v);
        }
        if let Some(v) = self.allow_npu {
            builder = builder.allow_npu(v);
        }
        if let Some(v) = self.allow_hardware {
            builder = builder.allow_hardware(v);
        }

        builder.build()
    }
}

/// Get strict security preset
#[napi]
pub fn security_config_strict() -> SecurityConfigJs {
    let rust = heel::SecurityConfig::strict();
    SecurityConfigJs {
        protect_user_home: Some(rust.protect_user_home),
        protect_credentials: Some(rust.protect_credentials),
        protect_cloud_config: Some(rust.protect_cloud_config),
        protect_browser_data: Some(rust.protect_browser_data),
        protect_keychain: Some(rust.protect_keychain),
        protect_shell_history: Some(rust.protect_shell_history),
        protect_package_credentials: Some(rust.protect_package_credentials),
        allow_gpu: Some(rust.allow_gpu),
        allow_npu: Some(rust.allow_npu),
        allow_hardware: Some(rust.allow_hardware),
    }
}

/// Get permissive security preset
#[napi]
pub fn security_config_permissive() -> SecurityConfigJs {
    let rust = heel::SecurityConfig::permissive();
    SecurityConfigJs {
        protect_user_home: Some(rust.protect_user_home),
        protect_credentials: Some(rust.protect_credentials),
        protect_cloud_config: Some(rust.protect_cloud_config),
        protect_browser_data: Some(rust.protect_browser_data),
        protect_keychain: Some(rust.protect_keychain),
        protect_shell_history: Some(rust.protect_shell_history),
        protect_package_credentials: Some(rust.protect_package_credentials),
        allow_gpu: Some(rust.allow_gpu),
        allow_npu: Some(rust.allow_npu),
        allow_hardware: Some(rust.allow_hardware),
    }
}
