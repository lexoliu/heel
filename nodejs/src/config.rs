//! Sandbox configuration from JavaScript.

use std::collections::HashMap;
use std::path::PathBuf;

use heel::{
    Access, Grant, NetworkPolicy, PathRequest, ResolvedPath, SandboxConfig, SandboxConfigBuilder,
    SecurityConfig,
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

/// The paths of a configuration as the caller wrote them.
struct PathPlan {
    grants: Vec<(PathBuf, Access)>,
    working_dir: Option<PathBuf>,
    venv: Option<(PathBuf, VenvAccess)>,
}

/// Whether the sandbox may write the virtual environment.
#[derive(Clone, Copy)]
enum VenvAccess {
    ReadOnly,
    Writable,
}

/// What a path is for, carried through resolution so each result finds its
/// place without being matched back by position.
enum Role {
    Grant(Access),
    WorkingDir,
    Venv,
}

/// The paths of a configuration, resolved.
#[derive(Default)]
pub struct ResolvedPaths {
    grants: Vec<Grant>,
    working_dir: Option<ResolvedPath>,
    venv: Option<ResolvedPath>,
}

impl PathPlan {
    /// Resolve every path, once, all together: a link inside a directory this
    /// configuration lets the sandbox write, or a writable path that is itself
    /// a link, is refused, because a sandbox of an earlier run may have planted
    /// it.
    fn resolve(self) -> heel::Result<ResolvedPaths> {
        let requests = self
            .grants
            .into_iter()
            .map(|(path, access)| {
                let request = if access.can_write() {
                    PathRequest::writable(path)
                } else {
                    PathRequest::readable(path)
                };
                (request, Role::Grant(access))
            })
            .chain(self.working_dir.into_iter().map(|dir| {
                (
                    PathRequest::writable(dir).allow_missing_tail(),
                    Role::WorkingDir,
                )
            }))
            .chain(self.venv.into_iter().map(|(path, access)| {
                let request = match access {
                    VenvAccess::Writable => PathRequest::writable(path),
                    VenvAccess::ReadOnly => PathRequest::readable(path),
                };
                (request, Role::Venv)
            }));

        let mut resolved = ResolvedPaths::default();
        for (path, role) in heel::resolve_paths(requests)? {
            match role {
                Role::Grant(access) => resolved.grants.push(Grant::new(path, access)),
                Role::WorkingDir => resolved.working_dir = Some(path),
                Role::Venv => resolved.venv = Some(path),
            }
        }
        Ok(resolved)
    }
}

impl SandboxConfigJs {
    fn path_plan(&self) -> Result<PathPlan> {
        let grants = self
            .grants
            .iter()
            .flatten()
            .map(|(path, mode)| -> Result<(PathBuf, Access)> {
                let access: Access = mode.parse().map_err(|error| {
                    Error::new(
                        Status::InvalidArg,
                        format!("[ERR_ACCESS_MODE] grants[\"{path}\"]: {error}"),
                    )
                })?;
                Ok((PathBuf::from(path), access))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(PathPlan {
            grants,
            working_dir: self.working_dir.as_ref().map(PathBuf::from),
            venv: self.python.as_ref().map(|python| {
                let access = if python.writes_environment() {
                    VenvAccess::Writable
                } else {
                    VenvAccess::ReadOnly
                };
                (python.venv_path(), access)
            }),
        })
    }

    /// Resolve the paths this configuration names, off the async thread. The
    /// library takes only resolved paths, so every path from JavaScript is
    /// resolved here before [`SandboxConfigJs::apply`].
    pub async fn resolve_paths(&self) -> Result<ResolvedPaths> {
        let plan = self.path_plan()?;
        blocking::unblock(move || plan.resolve())
            .await
            .map_err(convert_error)
    }

    /// Apply this configuration to a builder of the chosen policy type, with
    /// the paths [`SandboxConfigJs::resolve_paths`] resolved.
    pub fn apply<N: NetworkPolicy>(
        self,
        builder: SandboxConfigBuilder<N>,
        paths: ResolvedPaths,
    ) -> Result<SandboxConfig<N>> {
        let isolation = self.isolation.unwrap_or(IsolationJs::Default);
        let security = self
            .security
            .unwrap_or_default()
            .apply_to(isolation.security_preset());

        let mut builder = builder
            .security(security)
            .filesystem_strict(isolation.filesystem_strict())
            .writable_file_system(isolation.writable_file_system())
            .grants(paths.grants);

        if let Some(dir) = paths.working_dir {
            builder = builder.working_dir(dir.as_path());
        }
        if let (Some(python), Some(venv)) = (self.python, paths.venv) {
            builder = builder.python(python.into_rust(&venv)?);
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
        let paths = config
            .path_plan()?
            .resolve()
            .map_err(crate::error::convert_error)?;
        config.apply(SandboxConfig::builder(), paths)
    }

    /// `root/alias -> root/real` and the directory `root/real/granted`.
    fn aliased_grant(root: &std::path::Path) -> (PathBuf, PathBuf) {
        let real = root.join("real");
        std::fs::create_dir_all(real.join("granted")).expect("creates");
        symlink(&real, root.join("alias")).expect("links");
        (root.join("alias/granted"), real.join("granted"))
    }

    /// What a sandbox does between two runs.
    fn swap_for_link(directory: &std::path::Path, target: &std::path::Path) {
        std::fs::remove_dir_all(directory).expect("removes");
        symlink(target, directory).expect("links");
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
            [Grant::new(
                ResolvedPath::new(real.join("granted")).expect("resolved"),
                Access::WRITE
            )]
        );
    }

    #[test]
    fn a_grant_spelled_through_a_link_above_it_and_replaced_is_refused() {
        let (_guard, root) = resolved_dir();
        let (spelled, real) = aliased_grant(&root);
        let target = root.join("target");
        std::fs::create_dir(&target).expect("creates");
        apply(with_grant(&spelled, "rw")).expect("an unchanged grant resolves");
        swap_for_link(&real, &target);

        let error = apply(with_grant(&spelled, "rw")).err().expect("planted");

        assert!(
            error.reason.starts_with("[ERR_GRANT_REDIRECTED]"),
            "{}",
            error.reason
        );
    }

    #[test]
    fn a_working_directory_spelled_through_a_link_above_it_and_replaced_is_refused() {
        let (_guard, root) = resolved_dir();
        let (spelled, real) = aliased_grant(&root);
        let target = root.join("target");
        std::fs::create_dir(&target).expect("creates");
        swap_for_link(&real, &target);
        let config = SandboxConfigJs {
            working_dir: Some(spelled.to_string_lossy().into_owned()),
            ..preset_strict()
        };

        let error = apply(config).err().expect("planted");

        assert!(
            error.reason.starts_with("[ERR_GRANT_REDIRECTED]"),
            "{}",
            error.reason
        );
    }

    #[test]
    fn a_writable_environment_spelled_through_a_link_above_it_and_replaced_is_refused() {
        let (_guard, root) = resolved_dir();
        let (spelled, real) = aliased_grant(&root);
        let target = root.join("target");
        std::fs::create_dir(&target).expect("creates");
        swap_for_link(&real, &target);
        let config = SandboxConfigJs {
            python: Some(PythonConfigJs {
                venv: Some(VenvConfigJs {
                    path: Some(spelled.to_string_lossy().into_owned()),
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
