//! Bridge from the CLI's runtime configuration to the library's generics.

use heel::{
    AllowAll, AllowList, Audited, Command, DenyAll, NetworkAuditLog, NetworkPolicy, PythonConfig,
    Sandbox, SandboxConfig, SandboxConfigBuilder, VenvConfig,
};

use crate::cli::NetworkMode;
use crate::config::{MergedConfig, ResolvedPaths};
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
pub async fn create_sandbox(
    config: &MergedConfig,
    paths: &ResolvedPaths,
) -> CliResult<SandboxHandle> {
    let builder = SandboxConfigBuilder::default();
    match &config.ipc_endpoint {
        Some(endpoint) => {
            let endpoint = heel::ipc::TcpIpcEndpoint::resolve(endpoint, config.ipc_timeout).await?;
            create_with_builder(config, paths, builder.external_ipc(endpoint)).await
        }
        None => create_with_builder(config, paths, builder).await,
    }
}

async fn create_with_builder<I>(
    config: &MergedConfig,
    paths: &ResolvedPaths,
    builder: SandboxConfigBuilder<heel::DenyAll, I>,
) -> CliResult<SandboxHandle> {
    let venv = python_venv_config(config, paths);
    let audit = config
        .audit_log
        .as_deref()
        .map(NetworkAuditLog::file)
        .transpose()?;

    Ok(match (config.network_mode, audit) {
        (NetworkMode::Deny, _) => {
            SandboxHandle::DenyAll(Sandbox::with_config(build(builder, config, paths, venv)).await?)
        }
        (NetworkMode::Allow, None) => SandboxHandle::AllowAll(
            Sandbox::with_config(build(builder.network(AllowAll), config, paths, venv)).await?,
        ),
        (NetworkMode::Allow, Some(log)) => SandboxHandle::AuditedAllowAll(
            Sandbox::with_config(build(
                builder.network(Audited::new(AllowAll, log)),
                config,
                paths,
                venv,
            ))
            .await?,
        ),
        (NetworkMode::AllowList, None) => {
            let policy = AllowList::new(config.allow_domains.iter());
            SandboxHandle::AllowList(
                Sandbox::with_config(build(builder.network(policy), config, paths, venv)).await?,
            )
        }
        (NetworkMode::AllowList, Some(log)) => {
            let policy = Audited::new(AllowList::new(config.allow_domains.iter()), log);
            SandboxHandle::AuditedAllowList(
                Sandbox::with_config(build(builder.network(policy), config, paths, venv)).await?,
            )
        }
    })
}

/// Apply the merged configuration to a sandbox config builder.
fn build<N: NetworkPolicy, I>(
    builder: SandboxConfigBuilder<N, I>,
    config: &MergedConfig,
    paths: &ResolvedPaths,
    venv: Option<VenvConfig>,
) -> SandboxConfig<N> {
    let mut builder = builder
        .security(config.security.clone())
        .limits(config.limits.clone())
        .priority(config.priority)
        .grants(paths.grants.iter().cloned())
        .env_passthroughs(config.env_passthroughs.iter().cloned())
        .filesystem_strict(config.isolation.filesystem_strict())
        .writable_file_system(config.isolation.writable_file_system());

    if let Some(dir) = &paths.working_dir {
        builder = builder.working_dir(dir.as_path());
    }

    if let Some(venv) = venv {
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
///
/// The environment's path is the one `MergedConfig::resolve_paths` resolved.
pub fn python_venv_config(config: &MergedConfig, paths: &ResolvedPaths) -> Option<VenvConfig> {
    let python = &config.python;
    let venv = paths.venv.as_ref()?;

    let mut builder = VenvConfig::builder()
        .system_site_packages(python.system_site_packages)
        .backend(python.backend)
        .packages(python.packages.iter().cloned())
        .path(venv.as_path());
    if let Some(interpreter) = &python.interpreter {
        builder = builder.python(interpreter);
    }

    Some(builder.build())
}
