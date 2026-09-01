//! Bridge from the CLI's runtime configuration to the library's generics.

use heel::{
    AllowAll, AllowList, Audited, Command, DenyAll, NetworkAuditLog, NetworkPolicy, PythonConfig,
    Sandbox, SandboxConfig, SandboxConfigBuilder, VenvConfig,
};

use crate::cli::NetworkMode;
use crate::config::MergedConfig;
use crate::error::CliResult;

/// A sandbox whose network policy was chosen at runtime.
///
/// The library is generic over the policy so that policies compose at compile
/// time; the CLI picks one from a flag, so it needs this small dispatch layer.
pub enum SandboxHandle {
    DenyAll(Sandbox<DenyAll>),
    AllowAll(Sandbox<AllowAll>),
    AllowList(Sandbox<AllowList>),
    AuditedAllowAll(Sandbox<Audited<AllowAll>>),
    AuditedAllowList(Sandbox<Audited<AllowList>>),
}

/// Run the same expression against whichever policy the sandbox was built with.
macro_rules! dispatch {
    ($self:expr, $sandbox:ident => $body:expr) => {
        match $self {
            SandboxHandle::DenyAll($sandbox) => $body,
            SandboxHandle::AllowAll($sandbox) => $body,
            SandboxHandle::AllowList($sandbox) => $body,
            SandboxHandle::AuditedAllowAll($sandbox) => $body,
            SandboxHandle::AuditedAllowList($sandbox) => $body,
        }
    };
}

impl SandboxHandle {
    /// Build a command to run in the sandbox.
    pub fn command(&self, program: impl Into<String>) -> Command<'_> {
        dispatch!(self, sandbox => sandbox.command(program))
    }

    /// Keep the working directory after the sandbox is dropped.
    pub fn keep_working_dir(&mut self) {
        dispatch!(self, sandbox => {
            sandbox.keep_working_dir();
        });
    }

    /// Run an interactive command on a pseudo-terminal.
    #[cfg(target_os = "macos")]
    pub fn run_interactive(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
    ) -> heel::Result<std::process::ExitStatus> {
        dispatch!(self, sandbox => sandbox.run_interactive(program, args, envs))
    }
}

/// Create a sandbox from the merged configuration.
///
/// An `--audit-log` wraps the chosen policy in [`Audited`], which records every
/// verdict without changing any of them. Merging has already rejected the one
/// combination that would record nothing, a deny-all policy with no proxy.
pub async fn create_sandbox(config: &MergedConfig) -> CliResult<SandboxHandle> {
    let builder = SandboxConfigBuilder::default();
    let audit = config
        .audit_log
        .as_deref()
        .map(NetworkAuditLog::file)
        .transpose()?;

    Ok(match (config.network_mode, audit) {
        (NetworkMode::Deny, _) => {
            SandboxHandle::DenyAll(Sandbox::with_config(build(builder, config)).await?)
        }
        (NetworkMode::Allow, None) => SandboxHandle::AllowAll(
            Sandbox::with_config(build(builder.network(AllowAll), config)).await?,
        ),
        (NetworkMode::Allow, Some(log)) => SandboxHandle::AuditedAllowAll(
            Sandbox::with_config(build(builder.network(Audited::new(AllowAll, log)), config))
                .await?,
        ),
        (NetworkMode::AllowList, None) => {
            let policy = AllowList::new(config.allow_domains.iter());
            SandboxHandle::AllowList(
                Sandbox::with_config(build(builder.network(policy), config)).await?,
            )
        }
        (NetworkMode::AllowList, Some(log)) => {
            let policy = Audited::new(AllowList::new(config.allow_domains.iter()), log);
            SandboxHandle::AuditedAllowList(
                Sandbox::with_config(build(builder.network(policy), config)).await?,
            )
        }
    })
}

/// Apply the merged configuration to a sandbox config builder.
fn build<N: NetworkPolicy>(
    builder: SandboxConfigBuilder<N>,
    config: &MergedConfig,
) -> SandboxConfig<N> {
    let mut builder = builder
        .security(config.security.clone())
        .limits(config.limits.clone())
        .readable_paths(&config.readable_paths)
        .writable_paths(&config.writable_paths)
        .executable_paths(&config.executable_paths)
        .env_passthroughs(config.env_passthroughs.iter().cloned())
        .filesystem_strict(config.isolation.filesystem_strict())
        .writable_file_system(config.isolation.writable_file_system());

    if let Some(dir) = &config.working_dir {
        builder = builder.working_dir(dir);
    }

    if let Some(venv) = python_venv_config(config) {
        builder = builder.python(
            PythonConfig::builder()
                .venv(venv)
                .allow_pip_install(config.python.allow_pip_install)
                .build(),
        );
    }

    builder.build()
}

/// The virtual environment configuration, when Python was configured at all.
pub fn python_venv_config(config: &MergedConfig) -> Option<VenvConfig> {
    let python = &config.python;
    if python.venv.is_none() && python.packages.is_empty() {
        return None;
    }

    let mut builder = VenvConfig::builder()
        .system_site_packages(python.system_site_packages)
        .backend(python.backend)
        .packages(python.packages.iter().cloned());

    if let Some(path) = &python.venv {
        builder = builder.path(path);
    }
    if let Some(interpreter) = &python.interpreter {
        builder = builder.python(interpreter);
    }

    Some(builder.build())
}
