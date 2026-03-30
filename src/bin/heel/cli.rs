use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "heel")]
#[command(version)]
#[command(about = "Native sandbox for running untrusted code")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Path to config file (TOML)
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a command in the sandbox
    Run(RunArgs),

    /// Start an interactive shell in the sandbox
    Shell(ShellArgs),

    /// Run Python in the sandbox (REPL if no script)
    Python(PythonArgs),

    /// Invoke an IPC command inside a heel environment
    Ipc(IpcArgs),
}

#[derive(Args)]
pub struct RunArgs {
    /// Program to run
    pub program: String,

    /// Arguments to pass to the program
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,

    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Args)]
pub struct ShellArgs {
    /// Shell to use (defaults to $SHELL or /bin/sh)
    #[arg(long)]
    pub shell: Option<PathBuf>,

    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Args)]
pub struct PythonArgs {
    /// Python script to run (REPL if omitted)
    pub script: Option<PathBuf>,

    /// Arguments to pass to the script
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,

    /// Path to virtual environment
    #[arg(long)]
    pub venv: Option<PathBuf>,

    /// Python interpreter to use
    #[arg(long)]
    pub python: Option<PathBuf>,

    /// Package to install (can be repeated)
    #[arg(long = "package", short = 'p')]
    pub packages: Vec<String>,

    /// Enable system site packages
    #[arg(long)]
    pub system_site_packages: bool,

    /// Use uv for venv/package management
    #[arg(long)]
    pub use_uv: bool,

    /// Allow pip install from within sandbox
    #[arg(long)]
    pub allow_pip_install: bool,

    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Args)]
pub struct IpcArgs {
    /// IPC command name to invoke
    pub command: String,

    /// Arguments forwarded to the IPC command
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// Common arguments shared across subcommands
#[derive(Args)]
pub struct CommonArgs {
    // === Network ===
    /// Network policy
    #[arg(long, default_value = "deny", value_enum)]
    pub network: NetworkMode,

    /// Domain to allow (can be repeated, supports wildcards like *.example.com)
    #[arg(long = "allow-domain")]
    pub allow_domains: Vec<String>,

    // === Security Presets ===
    /// Use permissive security preset (default is strict)
    #[arg(long)]
    pub permissive: bool,

    // === Protection Toggles ===
    /// Protect user home directory
    #[arg(long, overrides_with = "no_protect_home")]
    pub protect_home: bool,

    #[arg(long, hide = true)]
    pub no_protect_home: bool,

    /// Protect SSH/GPG credentials
    #[arg(long, overrides_with = "no_protect_credentials")]
    pub protect_credentials: bool,

    #[arg(long, hide = true)]
    pub no_protect_credentials: bool,

    /// Protect cloud config (.aws, .kube, .docker)
    #[arg(long, overrides_with = "no_protect_cloud_config")]
    pub protect_cloud_config: bool,

    #[arg(long, hide = true)]
    pub no_protect_cloud_config: bool,

    /// Protect browser data
    #[arg(long, overrides_with = "no_protect_browser_data")]
    pub protect_browser_data: bool,

    #[arg(long, hide = true)]
    pub no_protect_browser_data: bool,

    /// Protect system keychain
    #[arg(long, overrides_with = "no_protect_keychain")]
    pub protect_keychain: bool,

    #[arg(long, hide = true)]
    pub no_protect_keychain: bool,

    /// Protect shell history
    #[arg(long, overrides_with = "no_protect_shell_history")]
    pub protect_shell_history: bool,

    #[arg(long, hide = true)]
    pub no_protect_shell_history: bool,

    /// Protect package manager credentials
    #[arg(long, overrides_with = "no_protect_package_credentials")]
    pub protect_package_credentials: bool,

    #[arg(long, hide = true)]
    pub no_protect_package_credentials: bool,

    // === Hardware Access ===
    /// Allow GPU access (Metal, CUDA, etc.)
    #[arg(long, overrides_with = "no_allow_gpu")]
    pub allow_gpu: bool,

    #[arg(long, hide = true)]
    pub no_allow_gpu: bool,

    /// Allow NPU/Neural Engine access
    #[arg(long, overrides_with = "no_allow_npu")]
    pub allow_npu: bool,

    #[arg(long, hide = true)]
    pub no_allow_npu: bool,

    /// Allow general hardware access
    #[arg(long, overrides_with = "no_allow_hardware")]
    pub allow_hardware: bool,

    #[arg(long, hide = true)]
    pub no_allow_hardware: bool,

    // === File Access ===
    /// Path to allow reading (can be repeated)
    #[arg(long = "readable")]
    pub readable_paths: Vec<PathBuf>,

    /// Path to allow writing (can be repeated)
    #[arg(long = "writable")]
    pub writable_paths: Vec<PathBuf>,

    /// Path to allow executing (can be repeated)
    #[arg(long = "executable")]
    pub executable_paths: Vec<PathBuf>,

    // === Resource Limits ===
    /// Maximum memory in bytes
    #[arg(long)]
    pub max_memory: Option<u64>,

    /// Maximum CPU time in seconds
    #[arg(long)]
    pub max_cpu_time: Option<u64>,

    /// Maximum file size in bytes
    #[arg(long)]
    pub max_file_size: Option<u64>,

    /// Maximum number of processes
    #[arg(long)]
    pub max_processes: Option<u32>,

    // === Working Directory ===
    /// Working directory for sandbox
    #[arg(long)]
    pub working_dir: Option<PathBuf>,

    /// Keep auto-created working directory after sandbox exits
    #[arg(long)]
    pub keep_working_dir: bool,

    // === Environment ===
    /// Environment variable to pass through (can be repeated)
    #[arg(long = "env-passthrough")]
    pub env_passthroughs: Vec<String>,

    /// Environment variable to set (KEY=VALUE, can be repeated)
    #[arg(long = "env", short = 'e')]
    pub envs: Vec<String>,
}

#[derive(ValueEnum, Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    /// Deny all network access
    #[default]
    Deny,
    /// Allow all network access
    Allow,
    /// Allow only specified domains
    AllowList,
}
