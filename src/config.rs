//! Sandbox configuration.
//!
//! [`SandboxConfig`] pairs a [`NetworkPolicy`] with the policy-independent
//! [`SandboxConfigData`] that platform backends consume. Building a config is
//! pure: no directories are created and no other I/O happens until
//! [`Sandbox`](crate::Sandbox) is constructed.

use std::path::{Path, PathBuf};

use crate::grant::{Access, Grant};
use crate::identity::Identity;
use crate::ipc::IpcRouter;
use crate::network::{DenyAll, NetworkPolicy};
use crate::policy::{ReadDenylist, WriteDenylist};
use crate::priority::ProcessPriority;
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

/// The inodes the Linux backend keeps ready for new entries in the directories
/// above a denied path.
///
/// Landlock can only grant, so a directory that holds a credential store, such
/// as the home directory, is granted entry by entry, and an entry created in it
/// later has no grant of its own. The backend serves such a creation by moving a
/// pre-created, already granted file or directory into place. Each count is
/// per group of directories that share a filesystem and the rights their
/// entries need, and when one runs out the creation fails with `ENOSPC` and the
/// log names this setting.
///
/// The defaults suit a build that creates a few temporary entries directly in
/// the home directory; a tool that creates thousands needs more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodePool {
    files: usize,
    directories: usize,
}

impl InodePool {
    /// A pool of `files` regular files and `directories` directories.
    pub const fn new(files: usize, directories: usize) -> Self {
        Self { files, directories }
    }

    /// How many regular files are kept ready.
    pub const fn files(&self) -> usize {
        self.files
    }

    /// How many directories are kept ready.
    pub const fn directories(&self) -> usize {
        self.directories
    }
}

impl Default for InodePool {
    fn default() -> Self {
        Self::new(256, 64)
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
    grants: Vec<Grant>,
    identity: Option<Identity>,
    network_deny_all: bool,
    python: Option<PythonConfig>,
    working_dir: PathBuf,
    working_dir_auto: bool,
    filesystem_strict: bool,
    writable_file_system: bool,
    read_denylist: Option<ReadDenylist>,
    write_denylist: Option<WriteDenylist>,
    inode_pool: InodePool,
    broker_sync_wake_up: bool,
    env_passthrough: Vec<String>,
    limits: ResourceLimits,
    priority: ProcessPriority,
    /// Path of the IPC socket, once the server is listening. `None` disables IPC.
    ipc_socket: Option<PathBuf>,
    ipc_bin_dir: Option<PathBuf>,
    /// Explicit path to the `heel` binary that IPC shims execute.
    heel_binary: Option<PathBuf>,
    external_ipc: Option<crate::ipc::TcpIpcEndpoint>,
    allow_tty_write: bool,
    /// Whether commands may be spawned under a per-command supervisor.
    #[cfg(target_os = "linux")]
    supervised_spawn: bool,
    /// The `heel` binary the supervisor runs as, resolved when the sandbox is
    /// created and executable inside it. `None` unless `supervised_spawn`.
    #[cfg(target_os = "linux")]
    supervisor_binary: Option<PathBuf>,
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

    /// The configured paths and what may be done with each.
    ///
    /// The working directory is not among them: it is always writable and never
    /// executable, which no configuration can change.
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// The identity shared by sandboxes that use its persistent profile.
    ///
    /// Without one, each sandbox uses an ephemeral profile of its own.
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
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

    /// The credential stores the sandbox must not read, if a policy is set.
    pub fn read_denylist(&self) -> Option<&ReadDenylist> {
        self.read_denylist.as_ref()
    }

    /// The persistence locations the sandbox must not write, if a policy is set.
    pub fn write_denylist(&self) -> Option<&WriteDenylist> {
        self.write_denylist.as_ref()
    }

    /// The inodes the Linux backend keeps ready for new entries in the
    /// directories above a denied path.
    pub fn inode_pool(&self) -> InodePool {
        self.inode_pool
    }

    /// Whether the Linux backend asks the kernel to wake its supervisor on the
    /// calling task's CPU.
    pub fn broker_sync_wake_up(&self) -> bool {
        self.broker_sync_wake_up
    }

    /// Fail when a platform backend cannot enforce what the configuration asks
    /// for beyond its grants.
    ///
    /// Host environment variables forwarded into the sandbox.
    pub fn env_passthrough(&self) -> &[String] {
        &self.env_passthrough
    }

    /// Resource limits applied to sandboxed processes.
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// The scheduling priority sandboxed processes run at.
    pub fn priority(&self) -> ProcessPriority {
        self.priority
    }

    /// The IPC socket path, once the IPC server is listening.
    pub fn ipc_socket(&self) -> Option<&Path> {
        self.ipc_socket.as_deref()
    }

    /// Private executable directory holding this sandbox's IPC entrypoints.
    pub fn ipc_bin_dir(&self) -> Option<&Path> {
        self.ipc_bin_dir.as_deref()
    }

    pub(crate) fn set_ipc_bin_dir(&mut self, path: PathBuf) {
        self.ipc_bin_dir = Some(path);
    }

    /// The configured `heel` binary that IPC shims execute, if one was set.
    pub fn heel_binary(&self) -> Option<&Path> {
        self.heel_binary.as_deref()
    }

    /// Trusted peer served through a protected local relay without child TCP access.
    pub fn external_ipc(&self) -> Option<crate::ipc::TcpIpcEndpoint> {
        self.external_ipc
    }

    /// Whether the sandboxed process may write to the controlling terminal.
    pub fn allow_tty_write(&self) -> bool {
        self.allow_tty_write
    }

    /// Whether commands may be spawned under a per-command supervisor.
    #[cfg(target_os = "linux")]
    pub fn supervised_spawn(&self) -> bool {
        self.supervised_spawn
    }

    /// The `heel` binary a supervised command runs under, once the sandbox
    /// has resolved it.
    #[cfg(target_os = "linux")]
    pub fn supervisor_binary(&self) -> Option<&Path> {
        self.supervisor_binary.as_deref()
    }

    /// Record the `heel` binary the supervisor runs as.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_supervisor_binary(&mut self, path: PathBuf) {
        self.supervisor_binary = Some(path);
    }

    /// Replace the working directory with its canonical, created form.
    pub(crate) fn set_working_dir(&mut self, path: PathBuf) {
        self.working_dir = path;
    }

    /// Record the IPC socket the server bound.
    pub(crate) fn set_ipc_socket(&mut self, path: Option<PathBuf>) {
        self.ipc_socket = path;
    }

    /// Add `access` to what the sandboxed process may do with `path`.
    ///
    /// A path granted twice keeps the union of both grants, so a directory that
    /// is listed as writable and as executable ends up both rather than
    /// whichever list a backend happened to read last.
    pub(crate) fn push_grant(&mut self, path: PathBuf, access: Access) {
        match self
            .grants
            .iter_mut()
            .find(|grant| grant.path() == path.as_path())
        {
            Some(existing) => existing.widen(access),
            None => self.grants.push(Grant::new(path, access)),
        }
    }

    #[cfg(not(windows))]
    pub(crate) fn adopt_persistent_grants(&mut self) {
        let grants = self
            .identity
            .as_ref()
            .map(|identity| identity.persistent_grants().to_vec())
            .unwrap_or_default();
        for grant in grants {
            self.push_grant(grant.path().to_path_buf(), grant.access());
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

/// Builder state before an IPC route has been selected.
pub struct IpcUnconfigured;

/// Builder state with exactly one IPC route selected.
pub struct IpcConfigured;

/// Builder for [`SandboxConfig`].
pub struct SandboxConfigBuilder<N: NetworkPolicy = DenyAll, I = IpcUnconfigured> {
    network: N,
    data: SandboxConfigData,
    ipc: Option<IpcRouter>,
    ipc_state: std::marker::PhantomData<I>,
}

impl Default for SandboxConfigBuilder<DenyAll> {
    fn default() -> Self {
        Self {
            network: DenyAll,
            data: SandboxConfigData {
                security: SecurityConfig::default(),
                grants: Vec::new(),
                identity: None,
                network_deny_all: DenyAll::DENIES_ALL,
                python: None,
                // Resolved on build(); replaced by the canonical path when the
                // sandbox creates it.
                working_dir: PathBuf::new(),
                working_dir_auto: true,
                filesystem_strict: true,
                writable_file_system: false,
                read_denylist: None,
                write_denylist: None,
                inode_pool: InodePool::default(),
                broker_sync_wake_up: true,
                env_passthrough: Vec::new(),
                limits: ResourceLimits::default(),
                priority: ProcessPriority::default(),
                ipc_socket: None,
                ipc_bin_dir: None,
                heel_binary: None,
                external_ipc: None,
                // Deny /dev/tty writes by default so all output is captured.
                allow_tty_write: false,
                #[cfg(target_os = "linux")]
                supervised_spawn: false,
                #[cfg(target_os = "linux")]
                supervisor_binary: None,
            },
            ipc: None,
            ipc_state: std::marker::PhantomData,
        }
    }
}

impl<N: NetworkPolicy, I> SandboxConfigBuilder<N, I> {
    /// Set the network policy, changing the configuration's type.
    pub fn network<M: NetworkPolicy>(self, policy: M) -> SandboxConfigBuilder<M, I> {
        let mut data = self.data;
        data.network_deny_all = M::DENIES_ALL;
        SandboxConfigBuilder {
            network: policy,
            data,
            ipc: self.ipc,
            ipc_state: self.ipc_state,
        }
    }

    /// Set the fine-grained protection toggles.
    pub fn security(mut self, security: SecurityConfig) -> Self {
        self.data.security = security;
        self
    }

    /// Run sandboxes under this identity; without one, each sandbox gets an
    /// ephemeral profile.
    ///
    /// Persistent grants use the identity's package SID on Windows. On macOS
    /// and Linux, they are added to each sandbox's ordinary policy and are not
    /// retained between sandboxes.
    pub fn identity(mut self, identity: Identity) -> Self {
        self.data.identity = Some(identity);
        self
    }

    /// Grant `access` on one path.
    ///
    /// Granting the same path twice keeps the union: `.writable(p).executable(p)`
    /// and `.grant(p, Access::WRITE | Access::EXEC)` configure the same sandbox.
    pub fn grant(mut self, path: impl AsRef<Path>, access: Access) -> Self {
        self.data.push_grant(path.as_ref().to_path_buf(), access);
        self
    }

    /// Apply several grants.
    pub fn grants(mut self, grants: impl IntoIterator<Item = Grant>) -> Self {
        for grant in grants {
            self.data
                .push_grant(grant.path().to_path_buf(), grant.access());
        }
        self
    }

    /// Allow reading one path: `.grant(path, Access::READ)`.
    pub fn readable(self, path: impl AsRef<Path>) -> Self {
        self.grant(path, Access::READ)
    }

    /// Allow reading and writing one path: `.grant(path, Access::WRITE)`.
    ///
    /// A path that is writable and not executable is denied execute, so nothing
    /// written there can be run.
    pub fn writable(self, path: impl AsRef<Path>) -> Self {
        self.grant(path, Access::WRITE)
    }

    /// Allow reading and executing one path: `.grant(path, Access::EXEC)`.
    ///
    /// The path may be a single file or a directory; a directory grants execute
    /// to everything beneath it. Every backend applies this after the denies
    /// that keep writable locations non-executable, so a path granted both ends
    /// up executable. That is what a build cache needs, and it gives up the
    /// write-then-execute guarantee for that path alone.
    pub fn executable(self, path: impl AsRef<Path>) -> Self {
        self.grant(path, Access::EXEC)
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

    /// Deny reads of credential stores and keys, whatever else is readable.
    ///
    /// Combined with `filesystem_strict(false)` this is a denylist read policy:
    /// everything is readable except the credentials, so a toolchain installed
    /// anywhere on the host works without being listed. Combined with
    /// `filesystem_strict(true)` it adds to the allowlist what the allowlist
    /// cannot say, such as the keychain services and agent sockets.
    ///
    /// The denial is enforced after every grant: a grant naming a denied path
    /// does not reopen it. macOS and Linux enforce it, and a sandbox that
    /// carries it on Windows fails at construction.
    pub fn read_denylist(mut self, denylist: ReadDenylist) -> Self {
        self.data.read_denylist = Some(denylist);
        self
    }

    /// Deny writes to persistence locations, whatever else is writable.
    ///
    /// Combined with `writable_file_system(true)` this is a denylist write
    /// policy: everything is writable except the places where a write persists
    /// as code that runs outside the sandbox later.
    ///
    /// The denial is enforced after every grant. macOS and Linux enforce it, and
    /// a sandbox that carries it on Windows fails at construction.
    pub fn write_denylist(mut self, denylist: WriteDenylist) -> Self {
        self.data.write_denylist = Some(denylist);
        self
    }

    /// How many inodes the Linux backend keeps ready for new entries in the
    /// directories above a denied path. Ignored elsewhere.
    ///
    /// See [`InodePool`].
    pub fn inode_pool(mut self, pool: InodePool) -> Self {
        self.data.inode_pool = pool;
        self
    }

    /// Whether the Linux backend asks the kernel to wake its supervisor on the
    /// calling task's CPU (the default). Ignored elsewhere.
    ///
    /// Waking on the caller's CPU spares a migration for each brokered call, but
    /// leaves the supervisor's other threads idle while one call is served, so
    /// whether it pays is a property of the machine and the build.
    pub fn broker_sync_wake_up(mut self, enabled: bool) -> Self {
        self.data.broker_sync_wake_up = enabled;
        self
    }

    /// Make the whole filesystem writable (permissive mode).
    ///
    /// Not supported on Windows: building a sandbox fails with
    /// [`Error::UnsupportedSetting`](crate::Error::UnsupportedSetting).
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

    /// Lower the scheduling priority of sandboxed processes.
    ///
    /// A nice level is relative to this process, as `nice -n` is: the sandbox
    /// runs that many steps below its host, capped at the kernel's lowest
    /// priority. The priority covers the sandboxed process and everything it
    /// spawns. The default lowers nothing, which is also what keeps the faster
    /// `posix_spawn` path available when no resource limit is set either.
    pub fn priority(mut self, priority: ProcessPriority) -> Self {
        self.data.priority = priority;
        self
    }
}

impl<N: NetworkPolicy> SandboxConfigBuilder<N, IpcUnconfigured> {
    fn configured(self) -> SandboxConfigBuilder<N, IpcConfigured> {
        SandboxConfigBuilder {
            network: self.network,
            data: self.data,
            ipc: self.ipc,
            ipc_state: std::marker::PhantomData,
        }
    }

    /// Expose host-side commands to sandboxed processes over IPC.
    ///
    /// # IPC state
    ///
    /// Selects the sole IPC route; a configured builder cannot select another.
    pub fn ipc(mut self, router: IpcRouter) -> SandboxConfigBuilder<N, IpcConfigured> {
        self.ipc = Some(router);
        self.configured()
    }

    /// Relay sandbox IPC to one explicitly trusted peer, keeping child networking denied.
    ///
    /// # IPC state
    ///
    /// Selects the sole IPC route; a configured builder cannot select another.
    /// ```compile_fail
    /// use heel::{SandboxConfigBuilder, ipc::{IpcRouter, TcpIpcEndpoint}};
    /// use std::time::Duration;
    /// let peer = TcpIpcEndpoint::new("127.0.0.1:7000".parse().unwrap(), Duration::from_secs(1));
    /// SandboxConfigBuilder::default().ipc(IpcRouter::new()).external_ipc(peer);
    /// ```
    pub fn external_ipc(
        mut self,
        endpoint: crate::ipc::TcpIpcEndpoint,
    ) -> SandboxConfigBuilder<N, IpcConfigured> {
        self.data.external_ipc = Some(endpoint);
        self.configured()
    }
}

impl<N: NetworkPolicy, I> SandboxConfigBuilder<N, I> {
    /// Use a specific `heel` binary for the generated IPC command shims.
    ///
    /// Without this the binary is found through `HEEL_BIN`, the running
    /// executable, or `PATH`. Set it when embedding heel in an application that
    /// ships its own copy.
    pub fn heel_binary(mut self, path: impl AsRef<Path>) -> Self {
        self.data.heel_binary = Some(path.as_ref().to_path_buf());
        self
    }

    /// Allow [`Command::spawn_supervised`](crate::Command::spawn_supervised).
    ///
    /// A supervised command runs under `heel supervise` inside the sandbox, so
    /// the sandbox has to be able to execute the `heel` binary (found as for
    /// [`heel_binary`](Self::heel_binary)). Creating the sandbox fails if that
    /// binary cannot be found.
    #[cfg(target_os = "linux")]
    pub fn supervised_spawn(mut self, enabled: bool) -> Self {
        self.data.supervised_spawn = enabled;
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
        .readable("/usr/share")
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
