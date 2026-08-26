//! Sandbox configuration from JavaScript.

use std::path::PathBuf;

use heel::{NetworkPolicy, SandboxConfig, SandboxConfigBuilder, SecurityConfig};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::policy::NetworkPolicyConfig;
use crate::python::{PythonConfigJs, VenvConfigJs};
use crate::security::SecurityConfigJs;

/// Resource limits for sandboxed processes.
#[napi(object)]
#[derive(Clone, Default)]
pub struct ResourceLimitsJs {
    /// Maximum address space, in bytes.
    pub max_memory_bytes: Option<i64>,
    /// Maximum CPU time, in seconds.
    pub max_cpu_time_secs: Option<i64>,
    /// Maximum size of a file the process may create, in bytes.
    pub max_file_size_bytes: Option<i64>,
    /// Maximum number of processes.
    pub max_processes: Option<i64>,
}

impl ResourceLimitsJs {
    fn into_rust(self) -> Result<heel::ResourceLimits> {
        let mut builder = heel::ResourceLimits::builder();

        // A limit is a promise about what the sandbox enforces, so a value that
        // cannot be enforced is rejected rather than quietly dropped.
        for (name, value) in [
            ("maxMemoryBytes", self.max_memory_bytes),
            ("maxCpuTimeSecs", self.max_cpu_time_secs),
            ("maxFileSizeBytes", self.max_file_size_bytes),
            ("maxProcesses", self.max_processes),
        ] {
            if let Some(value) = value
                && value < 0
            {
                return Err(Error::from_reason(format!(
                    "{name} must not be negative, got {value}"
                )));
            }
        }

        if let Some(value) = self.max_memory_bytes {
            builder = builder.max_memory_bytes(value as u64);
        }
        if let Some(value) = self.max_cpu_time_secs {
            builder = builder.max_cpu_time_secs(value as u64);
        }
        if let Some(value) = self.max_file_size_bytes {
            builder = builder.max_file_size_bytes(value as u64);
        }
        if let Some(value) = self.max_processes {
            builder = builder.max_processes(value as u64);
        }

        Ok(builder.build())
    }
}

/// How much of the host the sandbox can see.
#[napi(string_enum)]
pub enum IsolationJs {
    /// Only the working directory is readable or writable.
    Strict,
    /// The working directory is writable; the rest of the system is readable.
    Default,
    /// The whole filesystem is readable and writable.
    Permissive,
}

impl IsolationJs {
    fn security_preset(self) -> SecurityConfig {
        match self {
            Self::Strict | Self::Default => SecurityConfig::strict(),
            Self::Permissive => SecurityConfig::permissive(),
        }
    }

    fn filesystem_strict(self) -> bool {
        matches!(self, Self::Strict)
    }

    fn writable_file_system(self) -> bool {
        matches!(self, Self::Permissive)
    }
}

/// Sandbox configuration.
#[napi(object)]
pub struct SandboxConfigJs {
    /// Network policy; defaults to denying everything.
    pub network: Option<NetworkPolicyConfig>,
    /// Isolation level; defaults to `default`.
    pub isolation: Option<IsolationJs>,
    /// Security toggles layered onto the isolation level's preset.
    pub security: Option<SecurityConfigJs>,
    /// Paths the sandbox may write.
    pub writable_paths: Option<Vec<String>>,
    /// Paths the sandbox may read.
    pub readable_paths: Option<Vec<String>>,
    /// Paths the sandbox may execute.
    pub executable_paths: Option<Vec<String>>,
    /// Python configuration.
    pub python: Option<PythonConfigJs>,
    /// Working directory; generated when omitted.
    pub working_dir: Option<String>,
    /// Host environment variables to forward.
    pub env_passthrough: Option<Vec<String>>,
    /// Resource limits.
    pub limits: Option<ResourceLimitsJs>,
}

impl SandboxConfigJs {
    /// Apply this configuration to a builder of the chosen policy type.
    pub fn apply<N: NetworkPolicy>(
        self,
        builder: SandboxConfigBuilder<N>,
    ) -> Result<SandboxConfig<N>> {
        let isolation = self.isolation.unwrap_or(IsolationJs::Default);
        let security = self
            .security
            .unwrap_or_default()
            .apply_to(isolation.security_preset());

        let mut builder = builder
            .security(security)
            .filesystem_strict(isolation.filesystem_strict())
            .writable_file_system(isolation.writable_file_system());

        if let Some(paths) = self.writable_paths {
            builder = builder.writable_paths(paths.iter().map(PathBuf::from));
        }
        if let Some(paths) = self.readable_paths {
            builder = builder.readable_paths(paths.iter().map(PathBuf::from));
        }
        if let Some(paths) = self.executable_paths {
            builder = builder.executable_paths(paths.iter().map(PathBuf::from));
        }
        if let Some(python) = self.python {
            builder = builder.python(python.into_rust()?);
        }
        if let Some(dir) = self.working_dir {
            builder = builder.working_dir(dir);
        }
        if let Some(vars) = self.env_passthrough {
            builder = builder.env_passthroughs(vars);
        }
        if let Some(limits) = self.limits {
            builder = builder.limits(limits.into_rust()?);
        }

        Ok(builder.build())
    }
}

/// A sandbox that exposes only its own working directory, with no network.
#[napi]
pub fn preset_strict() -> SandboxConfigJs {
    SandboxConfigJs {
        network: None,
        isolation: Some(IsolationJs::Strict),
        security: None,
        writable_paths: None,
        readable_paths: None,
        executable_paths: None,
        python: None,
        working_dir: None,
        env_passthrough: None,
        limits: None,
    }
}

/// A sandbox for Python development, with writes to the virtual environment.
#[napi]
pub fn preset_python_dev() -> SandboxConfigJs {
    SandboxConfigJs {
        python: Some(PythonConfigJs {
            venv: None,
            allow_pip_install: Some(true),
        }),
        ..preset_strict()
    }
}

/// A sandbox for Python data science, with the usual toolchain preinstalled.
#[napi]
pub fn preset_python_data_science() -> SandboxConfigJs {
    SandboxConfigJs {
        isolation: Some(IsolationJs::Default),
        python: Some(PythonConfigJs {
            venv: Some(VenvConfigJs {
                packages: Some(vec![
                    "numpy".to_string(),
                    "pandas".to_string(),
                    "matplotlib".to_string(),
                    "scikit-learn".to_string(),
                ]),
                system_site_packages: Some(true),
                ..VenvConfigJs::default()
            }),
            allow_pip_install: Some(true),
        }),
        ..preset_strict()
    }
}
