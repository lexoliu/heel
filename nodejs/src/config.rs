//! Sandbox configuration from JavaScript.

use std::collections::HashMap;

use heel::{
    Access, Grant, NetworkPolicy, PathRequest, SandboxConfig, SandboxConfigBuilder, SecurityConfig,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::convert_error;
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
    /// The whole filesystem is readable and writable. Not supported on Windows.
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
    /// Paths the sandbox may use, each mapped to an access mode of `r`, `rw`, `rx` or `rwx`.
    /// Each path must exist; it is resolved once, when the sandbox is created, and a path
    /// crossing a link that a sandbox could have planted is refused.
    pub grants: Option<HashMap<String, String>>,
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

        // The library takes only resolved paths, so every path from JavaScript
        // is resolved here, once, all together: a link at or below a path this
        // configuration lets the sandbox write is refused, because a sandbox of
        // an earlier run may have planted it.
        let grants = self
            .grants
            .unwrap_or_default()
            .into_iter()
            .map(|(path, mode)| -> Result<(String, Access)> {
                let access: Access = mode.parse().map_err(|error| {
                    Error::new(
                        Status::InvalidArg,
                        format!("[ERR_ACCESS_MODE] grants[\"{path}\"]: {error}"),
                    )
                })?;
                Ok((path, access))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut requests: Vec<PathRequest> = grants
            .iter()
            .map(|(path, access)| PathRequest::new(path, access.can_write()))
            .collect();
        let grant_count = requests.len();
        requests.extend(
            self.working_dir
                .iter()
                .map(|dir| PathRequest::new(dir, true).allow_missing_tail()),
        );
        requests.extend(
            self.python
                .iter()
                .map(|python| PathRequest::new(python.venv_path(), python.writes_environment())),
        );
        let mut resolved = heel::resolve_paths(&requests)
            .map_err(convert_error)?
            .into_iter();

        builder = builder.grants(
            grants
                .iter()
                .zip(resolved.by_ref().take(grant_count))
                .map(|((_, access), path)| Grant::new(path, *access)),
        );
        // One resolved path per request, in request order.
        if let Some(dir) = self.working_dir.and_then(|_| resolved.next()) {
            builder = builder.working_dir(dir);
        }
        if let Some((python, venv)) = self.python.zip(resolved.next()) {
            builder = builder.python(python.into_rust(venv)?);
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
        grants: None,
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

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use super::*;

    fn resolved_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = std::fs::canonicalize(dir.path()).expect("resolves");
        (dir, path)
    }

    fn apply(config: SandboxConfigJs) -> Result<SandboxConfig<heel::DenyAll>> {
        config.apply(SandboxConfig::builder())
    }

    fn with_grant(path: &std::path::Path, mode: &str) -> SandboxConfigJs {
        SandboxConfigJs {
            grants: Some(HashMap::from([(
                path.to_string_lossy().into_owned(),
                mode.into(),
            )])),
            ..preset_strict()
        }
    }

    #[test]
    fn a_link_above_a_writable_grant_resolves() {
        let (_guard, root) = resolved_dir();
        let real = root.join("real");
        std::fs::create_dir_all(real.join("granted")).expect("creates");
        symlink(&real, root.join("alias")).expect("links");

        let config = apply(with_grant(&root.join("alias/granted"), "rw")).expect("resolves");

        assert_eq!(
            config.data().grants(),
            [Grant::new(real.join("granted"), Access::WRITE)]
        );
    }

    #[test]
    fn a_granted_directory_replaced_with_a_link_is_refused() {
        let (_guard, root) = resolved_dir();
        let (granted, target) = (root.join("granted"), root.join("target"));
        std::fs::create_dir_all(&target).expect("creates");
        symlink(&target, &granted).expect("links");

        let error = apply(with_grant(&granted, "rw")).err().expect("planted");

        assert!(
            error.reason.starts_with("[ERR_GRANT_REDIRECTED]"),
            "{}",
            error.reason
        );
    }

    #[test]
    fn a_missing_grant_is_an_err_path_error_naming_it() {
        let (_guard, root) = resolved_dir();
        let missing = root.join("absent");

        let error = apply(with_grant(&missing, "r")).err().expect("missing");

        assert!(error.reason.starts_with("[ERR_PATH]"), "{}", error.reason);
        assert!(
            error.reason.contains(&*missing.to_string_lossy()),
            "{}",
            error.reason
        );
    }

    #[test]
    fn an_environment_and_working_directory_are_resolved_with_the_grants() {
        let (_guard, root) = resolved_dir();
        let real = root.join("real");
        std::fs::create_dir_all(real.join("venv")).expect("creates");
        symlink(&real, root.join("alias")).expect("links");
        let config = SandboxConfigJs {
            python: Some(PythonConfigJs {
                venv: Some(VenvConfigJs {
                    path: Some(root.join("alias/venv").to_string_lossy().into_owned()),
                    ..VenvConfigJs::default()
                }),
                allow_pip_install: None,
            }),
            working_dir: Some(root.join("alias/work").to_string_lossy().into_owned()),
            ..preset_strict()
        };

        let config = apply(config).expect("resolves");

        let data = config.data();
        assert_eq!(data.working_dir(), real.join("work"));
        assert_eq!(
            data.python().expect("python").venv().path(),
            real.join("venv")
        );
    }

    #[test]
    fn a_writable_environment_replaced_with_a_link_is_refused() {
        let (_guard, root) = resolved_dir();
        let (venv, target) = (root.join("venv"), root.join("target"));
        std::fs::create_dir_all(&target).expect("creates");
        symlink(&target, &venv).expect("links");
        let config = SandboxConfigJs {
            python: Some(PythonConfigJs {
                venv: Some(VenvConfigJs {
                    path: Some(venv.to_string_lossy().into_owned()),
                    ..VenvConfigJs::default()
                }),
                allow_pip_install: Some(true),
            }),
            ..preset_strict()
        };

        let error = apply(config).err().expect("planted");

        assert!(
            error.reason.starts_with("[ERR_GRANT_REDIRECTED]"),
            "{}",
            error.reason
        );
    }
}
