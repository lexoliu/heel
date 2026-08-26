//! Sandbox configuration.
//!
//! [`SandboxConfig`] pairs a [`NetworkPolicy`] with the policy-independent
//! [`SandboxConfigData`] that platform backends consume. Building a config is
//! pure: no directories are created and no other I/O happens until
//! [`Sandbox`](crate::Sandbox) is constructed.

use std::path::{Path, PathBuf};

use crate::ipc::IpcRouter;
use crate::network::{DenyAll, NetworkPolicy};
use crate::security::SecurityConfig;
use crate::workdir::generate_working_dir_name;

/// Resource limits applied to sandboxed processes.
///
/// Limits are enforced with `setrlimit` after fork and before exec, so they
/// apply to the sandboxed process and everything it spawns.
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    max_memory_bytes: Option<u64>,
    max_cpu_time_secs: Option<u64>,
    max_file_size_bytes: Option<u64>,
    max_processes: Option<u64>,
}

impl ResourceLimits {
    /// Create a new builder for resource limits.
    pub fn builder() -> ResourceLimitsBuilder {
        ResourceLimitsBuilder::default()
    }

    /// Maximum address space, in bytes (`RLIMIT_AS`).
    pub fn max_memory_bytes(&self) -> Option<u64> {
        self.max_memory_bytes
    }

    /// Maximum CPU time, in seconds (`RLIMIT_CPU`).
    pub fn max_cpu_time_secs(&self) -> Option<u64> {
        self.max_cpu_time_secs
    }

    /// Maximum size of a file the process may create, in bytes (`RLIMIT_FSIZE`).
    pub fn max_file_size_bytes(&self) -> Option<u64> {
        self.max_file_size_bytes
    }

    /// Maximum number of processes for the sandboxed user (`RLIMIT_NPROC`).
    pub fn max_processes(&self) -> Option<u64> {
        self.max_processes
    }

    /// Whether any limit is set.
    pub fn is_empty(&self) -> bool {
        self.max_memory_bytes.is_none()
            && self.max_cpu_time_secs.is_none()
            && self.max_file_size_bytes.is_none()
            && self.max_processes.is_none()
    }
}

/// Builder for [`ResourceLimits`].
#[derive(Debug, Default)]
pub struct ResourceLimitsBuilder {
    inner: ResourceLimits,
}

impl ResourceLimitsBuilder {
    /// Limit the address space the sandboxed process may map.
    pub fn max_memory_bytes(mut self, bytes: u64) -> Self {
        self.inner.max_memory_bytes = Some(bytes);
        self
    }

    /// Limit CPU time; the process is killed with `SIGKILL` past the hard limit.
    pub fn max_cpu_time_secs(mut self, secs: u64) -> Self {
        self.inner.max_cpu_time_secs = Some(secs);
        self
    }

    /// Limit the size of files the sandboxed process may create.
    pub fn max_file_size_bytes(mut self, bytes: u64) -> Self {
        self.inner.max_file_size_bytes = Some(bytes);
        self
    }

    /// Limit the number of processes the sandboxed user may run.
    pub fn max_processes(mut self, count: u64) -> Self {
        self.inner.max_processes = Some(count);
        self
    }

    /// Finish building.
    pub fn build(self) -> ResourceLimits {
        self.inner
    }
}

/// The tool used to create a virtual environment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VenvBackend {
    /// Use `uv` when it is installed, and `python -m venv` otherwise.
    ///
    /// Either tool produces an environment that satisfies the configuration, so
    /// this picks the faster one when it is available rather than failing.
    #[default]
    Auto,
    /// Require `uv`, failing if it is not installed.
    Uv,
    /// Use `python -m venv`.
    Python,
}

/// Configuration for a Python virtual environment.
#[derive(Debug, Clone)]
pub struct VenvConfig {
    path: PathBuf,
    python: Option<PathBuf>,
    packages: Vec<String>,
    system_site_packages: bool,
    backend: VenvBackend,
}

impl Default for VenvConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(".sandbox-venv"),
            python: None,
            packages: Vec::new(),
            system_site_packages: true,
            backend: VenvBackend::default(),
        }
    }
}

impl VenvConfig {
    /// Create a new builder for [`VenvConfig`].
    pub fn builder() -> VenvConfigBuilder {
        VenvConfigBuilder::default()
    }

    /// Where the virtual environment lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The interpreter used to create the environment, if pinned.
    pub fn python(&self) -> Option<&Path> {
        self.python.as_deref()
    }

    /// Packages installed when the environment is created.
    pub fn packages(&self) -> &[String] {
        &self.packages
    }

    /// Whether the environment sees the system's site-packages.
    pub fn system_site_packages(&self) -> bool {
        self.system_site_packages
    }

    /// The tool used to create the environment.
    pub fn backend(&self) -> VenvBackend {
        self.backend
    }
}

/// Builder for [`VenvConfig`].
#[derive(Debug, Default)]
pub struct VenvConfigBuilder {
    inner: VenvConfig,
}

impl VenvConfigBuilder {
    /// Set where the environment lives.
    pub fn path(mut self, path: impl AsRef<Path>) -> Self {
        self.inner.path = path.as_ref().to_path_buf();
        self
    }

    /// Pin the interpreter used to create the environment.
    pub fn python(mut self, python: impl AsRef<Path>) -> Self {
        self.inner.python = Some(python.as_ref().to_path_buf());
        self
    }

    /// Install one package.
    pub fn package(mut self, pkg: impl Into<String>) -> Self {
        self.inner.packages.push(pkg.into());
        self
    }

    /// Install several packages.
    pub fn packages(mut self, pkgs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inner.packages.extend(pkgs.into_iter().map(Into::into));
        self
    }

    /// Expose the system's site-packages to the environment.
    pub fn system_site_packages(mut self, enabled: bool) -> Self {
        self.inner.system_site_packages = enabled;
        self
    }

    /// Choose the tool used to create the environment.
    pub fn backend(mut self, backend: VenvBackend) -> Self {
        self.inner.backend = backend;
        self
    }

    /// Finish building.
    pub fn build(self) -> VenvConfig {
        self.inner
    }
}

/// Python configuration for a sandbox.
#[derive(Debug, Clone, Default)]
pub struct PythonConfig {
    venv: VenvConfig,
    /// Writes are off by default: an environment the sandbox can change
    /// outlives the sandbox.
    allow_pip_install: bool,
}

impl PythonConfig {
    /// Create a new builder for [`PythonConfig`].
    pub fn builder() -> PythonConfigBuilder {
        PythonConfigBuilder::default()
    }

    /// The virtual environment configuration.
    pub fn venv(&self) -> &VenvConfig {
        &self.venv
    }

    /// Whether the sandboxed process may write to the virtual environment.
    ///
    /// When `false` the environment is mounted read-and-execute only, so
    /// `pip install` from inside the sandbox fails instead of mutating an
    /// environment that outlives the sandbox.
    pub fn allow_pip_install(&self) -> bool {
        self.allow_pip_install
    }
}

/// Builder for [`PythonConfig`].
#[derive(Debug, Default)]
pub struct PythonConfigBuilder {
    inner: PythonConfig,
}

impl PythonConfigBuilder {
    /// Set the virtual environment configuration.
    pub fn venv(mut self, config: VenvConfig) -> Self {
        self.inner.venv = config;
        self
    }

    /// Let the sandboxed process write to the virtual environment.
    pub fn allow_pip_install(mut self, enabled: bool) -> Self {
        self.inner.allow_pip_install = enabled;
        self
    }

    /// Finish building.
    pub fn build(self) -> PythonConfig {
        self.inner
    }
}

/// Sandbox configuration without the network policy.
///
/// The policy is generic over the sandbox type, so it is split out before the
/// configuration reaches the platform backends. Everything a backend needs to
/// build a profile lives here.
#[derive(Debug, Clone)]
pub struct SandboxConfigData {
    security: SecurityConfig,
    writable_paths: Vec<PathBuf>,
    readable_paths: Vec<PathBuf>,
    executable_paths: Vec<PathBuf>,
    network_deny_all: bool,
    python: Option<PythonConfig>,
    working_dir: PathBuf,
    working_dir_auto: bool,
    filesystem_strict: bool,
    writable_file_system: bool,
    env_passthrough: Vec<String>,
    limits: ResourceLimits,
    /// Path of the IPC socket, once the server is listening. `None` disables IPC.
    ipc_socket: Option<PathBuf>,
    /// Explicit path to the `heel` binary that IPC shims execute.
    heel_binary: Option<PathBuf>,
    allow_tty_write: bool,
}

impl SandboxConfigData {
    /// Whether the whole filesystem is writable (permissive mode).
    pub fn writable_file_system(&self) -> bool {
        self.writable_file_system
    }

    /// Fine-grained protection toggles.
    pub fn security(&self) -> &SecurityConfig {
        &self.security
    }

    /// Paths the sandboxed process may write.
    pub fn writable_paths(&self) -> &[PathBuf] {
        &self.writable_paths
    }

    /// Paths the sandboxed process may read.
    pub fn readable_paths(&self) -> &[PathBuf] {
        &self.readable_paths
    }

    /// Paths the sandboxed process may execute.
    pub fn executable_paths(&self) -> &[PathBuf] {
        &self.executable_paths
    }

    /// Whether the network policy rejects everything, letting the backend deny
    /// outbound traffic in the kernel instead of in the proxy.
    pub fn network_deny_all(&self) -> bool {
        self.network_deny_all
    }

    /// Python configuration, if any.
    pub fn python(&self) -> Option<&PythonConfig> {
        self.python.as_ref()
    }

    /// The sandbox working directory.
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    /// Whether the working directory path was generated rather than supplied.
    pub fn working_dir_is_auto(&self) -> bool {
        self.working_dir_auto
    }

    /// Whether reads outside the working directory and allow list are denied.
    pub fn filesystem_strict(&self) -> bool {
        self.filesystem_strict
    }

    /// Host environment variables forwarded into the sandbox.
    pub fn env_passthrough(&self) -> &[String] {
        &self.env_passthrough
    }

    /// Resource limits applied to sandboxed processes.
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// The IPC socket path, once the IPC server is listening.
    pub fn ipc_socket(&self) -> Option<&Path> {
        self.ipc_socket.as_deref()
    }

    /// The configured `heel` binary that IPC shims execute, if one was set.
    pub fn heel_binary(&self) -> Option<&Path> {
        self.heel_binary.as_deref()
    }

    /// Whether the sandboxed process may write to the controlling terminal.
    pub fn allow_tty_write(&self) -> bool {
        self.allow_tty_write
    }

    /// Replace the working directory with its canonical, created form.
    pub(crate) fn set_working_dir(&mut self, path: PathBuf) {
        self.working_dir = path;
    }

    /// Record the IPC socket the server bound.
    pub(crate) fn set_ipc_socket(&mut self, path: Option<PathBuf>) {
        self.ipc_socket = path;
    }

    /// Register a path the sandboxed process must be able to execute.
    pub(crate) fn push_executable_path(&mut self, path: PathBuf) {
        if !self.executable_paths.contains(&path) {
            self.executable_paths.push(path);
        }
    }
}

/// A sandbox configuration: a network policy plus everything else.
pub struct SandboxConfig<N: NetworkPolicy = DenyAll> {
    network: N,
    data: SandboxConfigData,
    ipc: Option<IpcRouter>,
}

impl SandboxConfig<DenyAll> {
    /// Create a configuration with default settings and no network access.
    pub fn new() -> Self {
        SandboxConfigBuilder::default().build()
    }

    /// Create a new builder.
    pub fn builder() -> SandboxConfigBuilder<DenyAll> {
        SandboxConfigBuilder::default()
    }
}

impl Default for SandboxConfig<DenyAll> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N: NetworkPolicy> SandboxConfig<N> {
    /// Split the configuration into its policy, its data, and its IPC router.
    pub(crate) fn into_parts(self) -> (N, SandboxConfigData, Option<IpcRouter>) {
        (self.network, self.data, self.ipc)
    }

    /// The network policy.
    pub fn network(&self) -> &N {
        &self.network
    }

    /// The policy-independent configuration.
    pub fn data(&self) -> &SandboxConfigData {
        &self.data
    }

    /// The IPC router, if one is registered.
    pub fn ipc(&self) -> Option<&IpcRouter> {
        self.ipc.as_ref()
    }
}

/// Builder for [`SandboxConfig`].
pub struct SandboxConfigBuilder<N: NetworkPolicy = DenyAll> {
    network: N,
    data: SandboxConfigData,
    ipc: Option<IpcRouter>,
}

impl Default for SandboxConfigBuilder<DenyAll> {
    fn default() -> Self {
        Self {
            network: DenyAll,
            data: SandboxConfigData {
                security: SecurityConfig::default(),
                writable_paths: Vec::new(),
                readable_paths: Vec::new(),
                executable_paths: Vec::new(),
                network_deny_all: DenyAll::DENIES_ALL,
                python: None,
                // Resolved on build(); replaced by the canonical path when the
                // sandbox creates it.
                working_dir: PathBuf::new(),
                working_dir_auto: true,
                filesystem_strict: true,
                writable_file_system: false,
                env_passthrough: Vec::new(),
                limits: ResourceLimits::default(),
                ipc_socket: None,
                heel_binary: None,
                // Deny /dev/tty writes by default so all output is captured.
                allow_tty_write: false,
            },
            ipc: None,
        }
    }
}

impl<N: NetworkPolicy> SandboxConfigBuilder<N> {
    /// Set the network policy, changing the configuration's type.
    pub fn network<M: NetworkPolicy>(self, policy: M) -> SandboxConfigBuilder<M> {
        let mut data = self.data;
        data.network_deny_all = M::DENIES_ALL;
        SandboxConfigBuilder {
            network: policy,
            data,
            ipc: self.ipc,
        }
    }

    /// Set the fine-grained protection toggles.
    pub fn security(mut self, security: SecurityConfig) -> Self {
        self.data.security = security;
        self
    }

    /// Allow writing one path.
    pub fn writable_path(mut self, path: impl AsRef<Path>) -> Self {
        self.data.writable_paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Allow writing several paths.
    pub fn writable_paths(mut self, paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Self {
        self.data
            .writable_paths
            .extend(paths.into_iter().map(|p| p.as_ref().to_path_buf()));
        self
    }

    /// Allow reading one path.
    pub fn readable_path(mut self, path: impl AsRef<Path>) -> Self {
        self.data.readable_paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Allow reading several paths.
    pub fn readable_paths(mut self, paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Self {
        self.data
            .readable_paths
            .extend(paths.into_iter().map(|p| p.as_ref().to_path_buf()));
        self
    }

    /// Allow executing one path.
    pub fn executable_path(mut self, path: impl AsRef<Path>) -> Self {
        self.data.executable_paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Allow executing several paths.
    pub fn executable_paths(mut self, paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Self {
        self.data
            .executable_paths
            .extend(paths.into_iter().map(|p| p.as_ref().to_path_buf()));
        self
    }

    /// Configure Python support.
    pub fn python(mut self, config: PythonConfig) -> Self {
        self.data.python = Some(config);
        self
    }

    /// Deny reads outside the working directory and the allow list.
    pub fn filesystem_strict(mut self, enabled: bool) -> Self {
        self.data.filesystem_strict = enabled;
        self
    }

    /// Make the whole filesystem writable (permissive mode).
    pub fn writable_file_system(mut self, enabled: bool) -> Self {
        self.data.writable_file_system = enabled;
        self
    }

    /// Use a specific working directory instead of a generated one.
    ///
    /// The directory is created when the sandbox starts if it does not exist.
    /// A directory supplied here is never deleted when the sandbox is dropped.
    pub fn working_dir(mut self, path: impl AsRef<Path>) -> Self {
        self.data.working_dir = path.as_ref().to_path_buf();
        self.data.working_dir_auto = false;
        self
    }

    /// Forward one host environment variable into the sandbox.
    pub fn env_passthrough(mut self, var: impl Into<String>) -> Self {
        self.data.env_passthrough.push(var.into());
        self
    }

    /// Forward several host environment variables into the sandbox.
    pub fn env_passthroughs(mut self, vars: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.data
            .env_passthrough
            .extend(vars.into_iter().map(Into::into));
        self
    }

    /// Apply resource limits to sandboxed processes.
    pub fn limits(mut self, limits: ResourceLimits) -> Self {
        self.data.limits = limits;
        self
    }

    /// Expose host-side commands to sandboxed processes over IPC.
    pub fn ipc(mut self, router: IpcRouter) -> Self {
        self.ipc = Some(router);
        self
    }

    /// Use a specific `heel` binary for the generated IPC command shims.
    ///
    /// Without this the binary is found through `HEEL_BIN`, the running
    /// executable, or `PATH`. Set it when embedding heel in an application that
    /// ships its own copy.
    pub fn heel_binary(mut self, path: impl AsRef<Path>) -> Self {
        self.data.heel_binary = Some(path.as_ref().to_path_buf());
        self
    }

    /// Let the sandboxed process write to the controlling terminal.
    ///
    /// When `false` (the default), output must go through the captured
    /// stdout/stderr pipes. Interactive sessions need this enabled.
    pub fn allow_tty_write(mut self, enabled: bool) -> Self {
        self.data.allow_tty_write = enabled;
        self
    }

    /// Finish building.
    ///
    /// This performs no I/O: the working directory is created when the sandbox
    /// is constructed.
    pub fn build(self) -> SandboxConfig<N> {
        let mut data = self.data;
        if data.working_dir_auto {
            data.working_dir = std::env::temp_dir().join(generate_working_dir_name());
        }

        SandboxConfig {
            network: self.network,
            data,
            ipc: self.ipc,
        }
    }
}

/// A sandbox that only exposes its own working directory, with no network.
pub fn strict_preset() -> SandboxConfig<DenyAll> {
    SandboxConfigBuilder::default()
        .filesystem_strict(true)
        .build()
}

/// A sandbox for Python development, with writes to the virtual environment.
pub fn python_dev_preset() -> SandboxConfig<DenyAll> {
    SandboxConfigBuilder::default()
        .python(PythonConfig::builder().allow_pip_install(true).build())
        .build()
}

/// A sandbox for Python data science, with the usual toolchain preinstalled.
pub fn python_data_science_preset() -> SandboxConfig<DenyAll> {
    SandboxConfigBuilder::default()
        .python(
            PythonConfig::builder()
                .venv(
                    VenvConfig::builder()
                        .packages(["numpy", "pandas", "matplotlib", "scikit-learn"])
                        .system_site_packages(true)
                        .build(),
                )
                .allow_pip_install(true)
                .build(),
        )
        .readable_path("/usr/share")
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{AllowAll, AllowList};

    #[test]
    fn default_config_denies_network_without_a_runtime_type_check() {
        let config = SandboxConfig::new();
        assert!(config.data().network_deny_all());
    }

    #[test]
    fn setting_a_permissive_policy_clears_the_deny_all_marker() {
        let config = SandboxConfig::builder().network(AllowAll).build();
        assert!(!config.data().network_deny_all());

        let config = SandboxConfig::builder()
            .network(AllowList::new(["example.com"]))
            .build();
        assert!(!config.data().network_deny_all());
    }

    #[test]
    fn building_creates_no_directories() {
        let config = SandboxConfig::new();
        assert!(config.data().working_dir_is_auto());
        assert!(
            !config.data().working_dir().exists(),
            "build() must not touch the filesystem"
        );
    }

    #[test]
    fn explicit_working_dir_is_not_auto() {
        let config = SandboxConfig::builder()
            .working_dir("/tmp/heel-fixed")
            .build();
        assert!(!config.data().working_dir_is_auto());
        assert_eq!(config.data().working_dir(), Path::new("/tmp/heel-fixed"));
    }

    #[test]
    fn generated_working_dirs_are_unique() {
        let first = SandboxConfig::new();
        let second = SandboxConfig::new();
        assert_ne!(first.data().working_dir(), second.data().working_dir());
    }
}
