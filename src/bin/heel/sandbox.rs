#[cfg(target_os = "macos")]
use heel::PtyExitStatus;
#[cfg(not(target_os = "macos"))]
use heel::StdioConfig;
use heel::{
    AllowAll, AllowList, Command, DenyAll, PythonConfig, Sandbox, SandboxConfig,
    SandboxConfigBuilder, VenvConfig,
};
#[cfg(target_os = "windows")]
use std::path::Path;
use std::path::PathBuf;

use crate::cli::NetworkMode;
use crate::config::MergedConfig;
use crate::error::{CliError, CliResult};

/// Type-erased sandbox handle for CLI use
///
/// This enum dispatches to the appropriate generic Sandbox type at runtime,
/// bridging the CLI's runtime configuration to the library's compile-time generics.
pub enum SandboxHandle {
    DenyAll(Sandbox<DenyAll>),
    AllowAll(Sandbox<AllowAll>),
    AllowList(Sandbox<AllowList>),
}

impl SandboxHandle {
    /// Create a command builder for running a program in the sandbox
    pub fn command(&self, program: impl Into<String>) -> Command<'_> {
        match self {
            Self::DenyAll(s) => s.command(program),
            Self::AllowAll(s) => s.command(program),
            Self::AllowList(s) => s.command(program),
        }
    }

    /// Keep the working directory after the sandbox is dropped
    pub fn keep_working_dir(&mut self) {
        match self {
            Self::DenyAll(s) => {
                s.keep_working_dir();
            }
            Self::AllowAll(s) => {
                s.keep_working_dir();
            }
            Self::AllowList(s) => {
                s.keep_working_dir();
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub async fn run_shell(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
    ) -> heel::Result<std::process::ExitStatus> {
        let mut command = self.command(program);
        command = command.args(args);
        for (key, value) in envs {
            command = command.env(key, value);
        }
        command
            .stdin(StdioConfig::Inherit)
            .stdout(StdioConfig::Inherit)
            .stderr(StdioConfig::Inherit)
            .status()
            .await
    }

    /// Run an interactive command with PTY support
    #[cfg(target_os = "macos")]
    pub fn run_interactive(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
    ) -> heel::Result<PtyExitStatus> {
        match self {
            Self::DenyAll(s) => s.run_interactive(program, args, envs),
            Self::AllowAll(s) => s.run_interactive(program, args, envs),
            Self::AllowList(s) => s.run_interactive(program, args, envs),
        }
    }
}

/// Create a sandbox from merged configuration
pub async fn create_sandbox(config: &MergedConfig) -> CliResult<SandboxHandle> {
    match config.network_mode {
        NetworkMode::Deny => {
            let sandbox_config = build_config(SandboxConfigBuilder::default(), config)?;
            let sandbox = Sandbox::with_config(sandbox_config).await?;
            Ok(SandboxHandle::DenyAll(sandbox))
        }
        NetworkMode::Allow => {
            let sandbox_config =
                build_config(SandboxConfigBuilder::default().network(AllowAll), config)?;
            let sandbox = Sandbox::with_config(sandbox_config).await?;
            Ok(SandboxHandle::AllowAll(sandbox))
        }
        NetworkMode::AllowList => {
            if config.allow_domains.is_empty() {
                return Err(CliError::MissingAllowDomains);
            }
            let policy = AllowList::new(config.allow_domains.iter().cloned());
            let sandbox_config =
                build_config(SandboxConfigBuilder::default().network(policy), config)?;
            let sandbox = Sandbox::with_config(sandbox_config).await?;
            Ok(SandboxHandle::AllowList(sandbox))
        }
    }
}

/// Build a SandboxConfig from merged CLI/file configuration
fn build_config<N: heel::NetworkPolicy>(
    builder: SandboxConfigBuilder<N>,
    config: &MergedConfig,
) -> CliResult<SandboxConfig<N>> {
    let executable_paths = effective_executable_paths(config);
    let mut builder = builder
        .security(config.security.clone())
        .limits(config.limits.clone())
        .readable_paths(config.readable_paths.iter().cloned())
        .writable_paths(config.writable_paths.iter().cloned())
        .executable_paths(executable_paths)
        .env_passthroughs(config.env_passthroughs.iter().cloned())
        .filesystem_strict(config.filesystem_strict)
        .writable_file_system(config.writable_file_system);

    // Set working directory if specified
    if let Some(ref dir) = config.working_dir {
        builder = builder.working_dir(dir);
    }

    // Add Python config if venv or packages are specified
    if config.python.venv.is_some() || !config.python.packages.is_empty() {
        let mut venv_builder = VenvConfig::builder();

        if let Some(ref venv_path) = config.python.venv {
            venv_builder = venv_builder.path(venv_path);
        }
        if let Some(ref interpreter) = config.python.interpreter {
            venv_builder = venv_builder.python(interpreter);
        }
        if !config.python.packages.is_empty() {
            venv_builder = venv_builder.packages(config.python.packages.iter().cloned());
        }
        venv_builder = venv_builder
            .system_site_packages(config.python.system_site_packages)
            .use_uv(config.python.use_uv);

        let python_config = PythonConfig::builder()
            .venv(venv_builder.build())
            .allow_pip_install(config.python.allow_pip_install)
            .build();

        builder = builder.python(python_config);
    }

    Ok(builder.build()?)
}

fn effective_executable_paths(config: &MergedConfig) -> Vec<PathBuf> {
    let mut paths = config.executable_paths.clone();
    add_windows_python_runtime_paths(&mut paths, config);
    paths
}

#[cfg(target_os = "windows")]
fn add_windows_python_runtime_paths(paths: &mut Vec<PathBuf>, config: &MergedConfig) {
    if let Some(interpreter) = &config.python.interpreter {
        push_python_runtime_root(paths, interpreter);
    }

    if let Some(venv) = &config.python.venv {
        paths.extend(pyvenv_runtime_roots(venv));
    }
}

#[cfg(not(target_os = "windows"))]
fn add_windows_python_runtime_paths(_paths: &mut Vec<PathBuf>, _config: &MergedConfig) {}

#[cfg(target_os = "windows")]
fn push_python_runtime_root(paths: &mut Vec<PathBuf>, python: &Path) {
    if let Some(parent) = python.parent() {
        paths.push(parent.to_path_buf());
    }
}

#[cfg(target_os = "windows")]
fn pyvenv_runtime_roots(venv_path: &Path) -> Vec<PathBuf> {
    let Ok(config) = std::fs::read_to_string(venv_path.join("pyvenv.cfg")) else {
        return Vec::new();
    };

    pyvenv_runtime_roots_from_text(&config)
}

#[cfg(target_os = "windows")]
fn pyvenv_runtime_roots_from_text(config: &str) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    for line in config.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        if value.is_empty() {
            continue;
        }

        if key.eq_ignore_ascii_case("home") {
            roots.push(PathBuf::from(value));
        } else if key.eq_ignore_ascii_case("executable")
            && let Some(parent) = Path::new(value).parent()
        {
            roots.push(parent.to_path_buf());
        }
    }

    roots
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    #[test]
    fn pyvenv_runtime_roots_parse_home_and_executable() {
        let roots = super::pyvenv_runtime_roots_from_text(
            "home = C:/Python314\nexecutable = C:/Python314/python.exe\n",
        );

        assert!(roots.iter().any(|path| path.ends_with("Python314")));
        assert_eq!(roots.len(), 2);
    }
}
