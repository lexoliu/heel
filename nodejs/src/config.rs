use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::IntoNapiResult;
use crate::network::{NetworkPolicyConfig, NetworkPolicyWrapper};
use crate::python::{PythonConfigJs, VenvConfigJs};
use crate::security::SecurityConfigJs;

/// Resource limits for sandboxed processes
#[napi(object)]
#[derive(Clone, Default)]
pub struct ResourceLimitsJs {
    /// Maximum memory in bytes
    pub max_memory_bytes: Option<i64>,
    /// Maximum CPU time in seconds
    pub max_cpu_time_secs: Option<i64>,
    /// Maximum file size in bytes
    pub max_file_size_bytes: Option<i64>,
    /// Maximum number of processes
    pub max_processes: Option<u32>,
}

impl ResourceLimitsJs {
    pub fn into_rust(self) -> heel::ResourceLimits {
        let mut builder = heel::ResourceLimits::builder();

        if let Some(v) = self.max_memory_bytes
            && v > 0
        {
            builder = builder.max_memory_bytes(v as u64);
        }
        if let Some(v) = self.max_cpu_time_secs
            && v > 0
        {
            builder = builder.max_cpu_time_secs(v as u64);
        }
        if let Some(v) = self.max_file_size_bytes
            && v > 0
        {
            builder = builder.max_file_size_bytes(v as u64);
        }
        if let Some(v) = self.max_processes {
            builder = builder.max_processes(v);
        }

        builder.build()
    }
}

/// Main sandbox configuration from JavaScript
#[napi(object)]
pub struct SandboxConfigJs {
    /// Network policy configuration
    pub network: Option<NetworkPolicyConfig>,
    /// Security configuration
    pub security: Option<SecurityConfigJs>,
    /// Enable strict filesystem mode (deny reads outside sandbox/allowlist)
    pub filesystem_strict: Option<bool>,
    /// Paths with write access
    pub writable_paths: Option<Vec<String>>,
    /// Paths with read-only access
    pub readable_paths: Option<Vec<String>>,
    /// Paths with execute access
    pub executable_paths: Option<Vec<String>>,
    /// Python configuration
    pub python: Option<PythonConfigJs>,
    /// Working directory path
    pub working_dir: Option<String>,
    /// Environment variables to pass through
    pub env_passthrough: Option<Vec<String>>,
    /// Resource limits
    pub limits: Option<ResourceLimitsJs>,
    // Note: IPC is handled separately at a higher level
}

impl SandboxConfigJs {
    /// Convert to Rust SandboxConfig with NetworkPolicyWrapper
    pub fn into_rust_config(self) -> Result<heel::SandboxConfig<NetworkPolicyWrapper>> {
        // Parse network policy
        let network_policy = match self.network {
            Some(config) => NetworkPolicyWrapper::from_config(config)?,
            None => NetworkPolicyWrapper::deny_all(),
        };

        // Start building the config
        let mut builder = heel::SandboxConfig::builder().network(network_policy);

        // Security config
        if let Some(security) = self.security {
            builder = builder.security(security.into_rust());
        }
        if let Some(strict_fs) = self.filesystem_strict {
            builder = builder.filesystem_strict(strict_fs);
        }

        // Path configurations
        if let Some(paths) = self.writable_paths {
            builder = builder.writable_paths(paths.iter().map(PathBuf::from));
        }
        if let Some(paths) = self.readable_paths {
            builder = builder.readable_paths(paths.iter().map(PathBuf::from));
        }
        if let Some(paths) = self.executable_paths {
            builder = builder.executable_paths(paths.iter().map(PathBuf::from));
        }

        // Python config
        if let Some(python) = self.python {
            builder = builder.python(python.into_rust());
        }

        // Working directory
        if let Some(dir) = self.working_dir {
            builder = builder.working_dir(dir);
        }

        // Environment passthrough
        if let Some(vars) = self.env_passthrough {
            builder = builder.env_passthroughs(vars);
        }

        // Resource limits
        if let Some(limits) = self.limits {
            builder = builder.limits(limits.into_rust());
        }

        builder.build().into_napi()
    }
}

/// Get strict sandbox preset configuration
#[napi]
pub fn preset_strict() -> SandboxConfigJs {
    SandboxConfigJs {
        network: None,  // DenyAll
        security: None, // Strict by default
        filesystem_strict: Some(true),
        writable_paths: None,
        readable_paths: None,
        executable_paths: None,
        python: None,
        working_dir: None,
        env_passthrough: None,
        limits: None,
    }
}

/// Get Python dev sandbox preset configuration
#[napi]
pub fn preset_python_dev() -> SandboxConfigJs {
    SandboxConfigJs {
        network: None,
        security: None,
        filesystem_strict: None,
        writable_paths: None,
        readable_paths: None,
        executable_paths: None,
        python: Some(PythonConfigJs {
            venv: None,
            allow_pip_install: Some(true),
        }),
        working_dir: None,
        env_passthrough: None,
        limits: None,
    }
}

/// Get Python data science sandbox preset configuration
#[napi]
pub fn preset_python_data_science() -> SandboxConfigJs {
    SandboxConfigJs {
        network: None,
        security: None,
        filesystem_strict: None,
        writable_paths: None,
        readable_paths: Some(vec!["/usr/share".to_string()]),
        executable_paths: Some(vec![
            "/usr/bin/ffmpeg".to_string(),
            "/usr/local/bin/ffmpeg".to_string(),
        ]),
        python: Some(PythonConfigJs {
            venv: Some(VenvConfigJs {
                path: None,
                python: None,
                packages: Some(vec![
                    "numpy".to_string(),
                    "pandas".to_string(),
                    "matplotlib".to_string(),
                    "scikit-learn".to_string(),
                ]),
                system_site_packages: Some(true),
                use_uv: Some(true),
            }),
            allow_pip_install: Some(true),
        }),
        working_dir: None,
        env_passthrough: None,
        limits: None,
    }
}
