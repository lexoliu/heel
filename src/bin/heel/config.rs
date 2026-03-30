use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use heel::{ResourceLimits, SecurityConfig, SecurityConfigBuilder};

use crate::cli::{CommonArgs, NetworkMode, PythonArgs};
use crate::error::{CliError, CliResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    /// Most restricted, only allow read/write within sandbox's workdir.
    Strict,
    /// Secure default for untrusted code (strict filesystem + sensitive-data protections).
    Default,
    /// Least restricted, allow read/write access to all directories.
    Permissive,
}

/// TOML config file structure
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FileConfig {
    /// Network policy: "deny", "allow", or "allow-list"
    pub network: Option<String>,
    /// Domains to allow (for allow-list policy)
    pub allow_domains: Option<Vec<String>>,

    /// Security settings
    pub security: SecuritySection,

    /// Path settings
    pub paths: PathsSection,

    /// Resource limits
    pub limits: LimitsSection,

    /// Working directory settings
    pub workdir: WorkdirSection,

    /// Environment settings
    pub env: EnvSection,

    /// Python settings
    pub python: PythonSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SecuritySection {
    /// Preset: "strict", "default", or "permissive"
    pub preset: Option<Preset>,
    pub protect_home: Option<bool>,
    pub protect_credentials: Option<bool>,
    pub protect_cloud_config: Option<bool>,
    pub protect_browser_data: Option<bool>,
    pub protect_keychain: Option<bool>,
    pub protect_shell_history: Option<bool>,
    pub protect_package_credentials: Option<bool>,
    pub allow_gpu: Option<bool>,
    pub allow_npu: Option<bool>,
    pub allow_hardware: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PathsSection {
    pub readable: Option<Vec<PathBuf>>,
    pub writable: Option<Vec<PathBuf>>,
    pub executable: Option<Vec<PathBuf>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LimitsSection {
    pub max_memory: Option<u64>,
    pub max_cpu_time: Option<u64>,
    pub max_file_size: Option<u64>,
    pub max_processes: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WorkdirSection {
    pub path: Option<PathBuf>,
    pub keep: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct EnvSection {
    pub passthrough: Option<Vec<String>>,
    pub set: Option<HashMap<String, String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PythonSection {
    pub venv: Option<PathBuf>,
    pub interpreter: Option<PathBuf>,
    pub packages: Option<Vec<String>>,
    pub system_site_packages: Option<bool>,
    pub use_uv: Option<bool>,
    pub allow_pip_install: Option<bool>,
}

/// Merged configuration from file + CLI
pub struct MergedConfig {
    pub network_mode: NetworkMode,
    pub allow_domains: Vec<String>,
    pub security: SecurityConfig,
    pub readable_paths: Vec<PathBuf>,
    pub writable_paths: Vec<PathBuf>,
    pub executable_paths: Vec<PathBuf>,
    pub limits: ResourceLimits,
    pub working_dir: Option<PathBuf>,
    pub keep_working_dir: bool,
    pub env_passthroughs: Vec<String>,
    pub env_set: HashMap<String, String>,
    pub filesystem_strict: bool,
    pub writable_file_system: bool,
    pub python: MergedPythonConfig,
}

pub struct MergedPythonConfig {
    pub venv: Option<PathBuf>,
    pub interpreter: Option<PathBuf>,
    pub packages: Vec<String>,
    pub system_site_packages: bool,
    pub use_uv: bool,
    pub allow_pip_install: bool,
}

impl Default for MergedPythonConfig {
    fn default() -> Self {
        Self {
            venv: None,
            interpreter: None,
            packages: Vec::new(),
            system_site_packages: true,
            use_uv: true,
            allow_pip_install: false,
        }
    }
}

/// Load config from file
pub fn load_config(path: Option<&Path>) -> CliResult<FileConfig> {
    match path {
        Some(path) => {
            let content = std::fs::read_to_string(path).map_err(|source| CliError::ReadConfig {
                path: path.to_path_buf(),
                source,
            })?;
            let config: FileConfig =
                toml::from_str(&content).map_err(|source| CliError::ParseConfig {
                    path: path.to_path_buf(),
                    source,
                })?;
            Ok(config)
        }
        None => Ok(FileConfig::default()),
    }
}

/// Merge file config with CLI args (CLI takes precedence)
pub fn merge_config(file: FileConfig, cli: &CommonArgs) -> CliResult<MergedConfig> {
    // Network mode: CLI > file > default (deny)
    let network_mode = if cli.network != NetworkMode::Deny {
        cli.network
    } else if let Some(ref net) = file.network {
        match net.as_str() {
            "deny" => NetworkMode::Deny,
            "allow" => NetworkMode::Allow,
            "allow-list" => NetworkMode::AllowList,
            other => {
                return Err(CliError::InvalidNetworkMode {
                    value: other.to_string(),
                });
            }
        }
    } else {
        NetworkMode::Deny
    };

    // Allow domains: merge CLI + file
    let mut allow_domains = file.allow_domains.unwrap_or_default();
    allow_domains.extend(cli.allow_domains.iter().cloned());

    // Security config & Preset
    let (security, filesystem_strict, writable_file_system) =
        build_security_and_preset(&file.security, cli);

    // Paths: merge CLI + file
    let mut readable_paths = file.paths.readable.unwrap_or_default();
    readable_paths.extend(cli.readable_paths.iter().cloned());

    let mut writable_paths = file.paths.writable.unwrap_or_default();
    writable_paths.extend(cli.writable_paths.iter().cloned());

    let mut executable_paths = file.paths.executable.unwrap_or_default();
    executable_paths.extend(cli.executable_paths.iter().cloned());

    // Resource limits: CLI > file
    let limits = build_resource_limits(&file.limits, cli);

    // Working directory: CLI > file
    let working_dir = cli.working_dir.clone().or(file.workdir.path);

    let keep_working_dir = cli.keep_working_dir || file.workdir.keep.unwrap_or(false);

    // Environment: merge
    let mut env_passthroughs = file.env.passthrough.unwrap_or_default();
    env_passthroughs.extend(cli.env_passthroughs.iter().cloned());

    let mut env_set = file.env.set.unwrap_or_default();
    for env_str in &cli.envs {
        if let Some((key, value)) = env_str.split_once('=') {
            env_set.insert(key.to_string(), value.to_string());
        } else {
            return Err(CliError::InvalidEnvFormat {
                value: env_str.clone(),
            });
        }
    }

    // Python config (from file only, PythonArgs handles its own)
    let python = MergedPythonConfig {
        venv: file.python.venv,
        interpreter: file.python.interpreter,
        packages: file.python.packages.unwrap_or_default(),
        system_site_packages: file.python.system_site_packages.unwrap_or(true),
        use_uv: file.python.use_uv.unwrap_or(true),
        allow_pip_install: file.python.allow_pip_install.unwrap_or(false),
    };

    Ok(MergedConfig {
        network_mode,
        allow_domains,
        security,
        readable_paths,
        writable_paths,
        executable_paths,
        limits,
        working_dir,
        keep_working_dir,
        env_passthroughs,
        env_set,
        filesystem_strict,
        writable_file_system,
        python,
    })
}

/// Merge Python args into merged config
pub fn merge_python_args(config: &mut MergedConfig, args: &PythonArgs) {
    // CLI python args override file config
    if args.venv.is_some() {
        config.python.venv = args.venv.clone();
    }
    if args.python.is_some() {
        config.python.interpreter = args.python.clone();
    }
    if !args.packages.is_empty() {
        config.python.packages.extend(args.packages.iter().cloned());
    }
    if args.system_site_packages {
        config.python.system_site_packages = true;
    }
    if args.use_uv {
        config.python.use_uv = true;
    }
    if args.allow_pip_install {
        config.python.allow_pip_install = true;
    }
}

fn build_security_and_preset(
    file: &SecuritySection,
    cli: &CommonArgs,
) -> (SecurityConfig, bool, bool) {
    // Determine preset: CLI > file > default (Default)
    let preset = if cli.permissive {
        Preset::Permissive
    } else {
        file.preset.unwrap_or(Preset::Default)
    };

    let mut builder = match preset {
        Preset::Strict => SecurityConfigBuilder::default(), // Strict security
        Preset::Default => SecurityConfigBuilder::default(), // Strict security
        Preset::Permissive => SecurityConfigBuilder::from_permissive(), // Permissive security
    };

    // Apply file config first, then CLI overrides

    // protect_home
    if let Some(v) = file.protect_home {
        builder = builder.protect_user_home(v);
    }
    if cli.protect_home {
        builder = builder.protect_user_home(true);
    } else if cli.no_protect_home {
        builder = builder.protect_user_home(false);
    }

    // protect_credentials
    if let Some(v) = file.protect_credentials {
        builder = builder.protect_credentials(v);
    }
    if cli.protect_credentials {
        builder = builder.protect_credentials(true);
    } else if cli.no_protect_credentials {
        builder = builder.protect_credentials(false);
    }

    // protect_cloud_config
    if let Some(v) = file.protect_cloud_config {
        builder = builder.protect_cloud_config(v);
    }
    if cli.protect_cloud_config {
        builder = builder.protect_cloud_config(true);
    } else if cli.no_protect_cloud_config {
        builder = builder.protect_cloud_config(false);
    }

    // protect_browser_data
    if let Some(v) = file.protect_browser_data {
        builder = builder.protect_browser_data(v);
    }
    if cli.protect_browser_data {
        builder = builder.protect_browser_data(true);
    } else if cli.no_protect_browser_data {
        builder = builder.protect_browser_data(false);
    }

    // protect_keychain
    if let Some(v) = file.protect_keychain {
        builder = builder.protect_keychain(v);
    }
    if cli.protect_keychain {
        builder = builder.protect_keychain(true);
    } else if cli.no_protect_keychain {
        builder = builder.protect_keychain(false);
    }

    // protect_shell_history
    if let Some(v) = file.protect_shell_history {
        builder = builder.protect_shell_history(v);
    }
    if cli.protect_shell_history {
        builder = builder.protect_shell_history(true);
    } else if cli.no_protect_shell_history {
        builder = builder.protect_shell_history(false);
    }

    // protect_package_credentials
    if let Some(v) = file.protect_package_credentials {
        builder = builder.protect_package_credentials(v);
    }
    if cli.protect_package_credentials {
        builder = builder.protect_package_credentials(true);
    } else if cli.no_protect_package_credentials {
        builder = builder.protect_package_credentials(false);
    }

    // allow_gpu
    if let Some(v) = file.allow_gpu {
        builder = builder.allow_gpu(v);
    }
    if cli.allow_gpu {
        builder = builder.allow_gpu(true);
    } else if cli.no_allow_gpu {
        builder = builder.allow_gpu(false);
    }

    // allow_npu
    if let Some(v) = file.allow_npu {
        builder = builder.allow_npu(v);
    }
    if cli.allow_npu {
        builder = builder.allow_npu(true);
    } else if cli.no_allow_npu {
        builder = builder.allow_npu(false);
    }

    // allow_hardware
    if let Some(v) = file.allow_hardware {
        builder = builder.allow_hardware(v);
    }
    if cli.allow_hardware {
        builder = builder.allow_hardware(true);
    } else if cli.no_allow_hardware {
        builder = builder.allow_hardware(false);
    }

    let config = builder.build();

    // Determine filesystem_strict based on preset
    let filesystem_strict = match preset {
        Preset::Strict => true,
        Preset::Default => true,
        Preset::Permissive => false,
    };

    // Determine writable_file_system based on preset (only Permissive allows global write)
    let writable_file_system = matches!(preset, Preset::Permissive);

    (config, filesystem_strict, writable_file_system)
}

fn build_resource_limits(file: &LimitsSection, cli: &CommonArgs) -> ResourceLimits {
    let mut builder = ResourceLimits::builder();

    // CLI > file for each limit
    let max_memory = cli.max_memory.or(file.max_memory);
    if let Some(v) = max_memory {
        builder = builder.max_memory_bytes(v);
    }

    let max_cpu_time = cli.max_cpu_time.or(file.max_cpu_time);
    if let Some(v) = max_cpu_time {
        builder = builder.max_cpu_time_secs(v);
    }

    let max_file_size = cli.max_file_size.or(file.max_file_size);
    if let Some(v) = max_file_size {
        builder = builder.max_file_size_bytes(v);
    }

    let max_processes = cli.max_processes.or(file.max_processes);
    if let Some(v) = max_processes {
        builder = builder.max_processes(v);
    }

    builder.build()
}
