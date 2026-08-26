use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use heel::SecurityOverrides;
use serde::Deserialize;

/// Native sandbox for running untrusted code.
#[derive(Parser)]
#[command(name = "heel", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    /// Whether verbose logging was requested.
    pub fn verbose(&self) -> bool {
        match &self.command {
            Commands::Run(args) => args.common.verbose,
            Commands::Shell(args) => args.common.verbose,
            Commands::Python(args) => args.common.verbose,
            Commands::Ipc(args) => args.verbose,
        }
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a command in the sandbox.
    Run(RunArgs),

    /// Start an interactive shell in the sandbox.
    Shell(ShellArgs),

    /// Run Python in the sandbox, or a REPL when no script is given.
    Python(PythonArgs),

    /// Invoke a host IPC command from inside a sandbox.
    Ipc(IpcArgs),
}

#[derive(Args)]
pub struct RunArgs {
    /// The program to run, followed by its own arguments.
    ///
    /// Program and arguments are one list so that everything after the program
    /// name reaches the program untouched. Parsed separately, a flag such as
    /// the `-c` of `heel run /bin/sh -c "..."` would be matched against heel's
    /// own options before the program ever saw it.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,

    #[command(flatten)]
    pub common: CommonArgs,
}

impl RunArgs {
    /// The program to run.
    pub fn program(&self) -> &str {
        self.command.first().map_or("", String::as_str)
    }

    /// The arguments to pass to it.
    pub fn args(&self) -> &[String] {
        self.command.get(1..).unwrap_or_default()
    }
}

#[derive(Args)]
pub struct ShellArgs {
    /// Shell to use; defaults to `$SHELL`, then `/bin/sh`.
    #[arg(long)]
    pub shell: Option<PathBuf>,

    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Args)]
pub struct PythonArgs {
    /// The script to run, followed by its own arguments.
    ///
    /// Starts a REPL when empty. As with `heel run`, this is one list so that
    /// the script's own flags are not matched against heel's.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,

    /// Path to the virtual environment.
    #[arg(long)]
    pub venv: Option<PathBuf>,

    /// Python interpreter to use.
    #[arg(long)]
    pub python: Option<PathBuf>,

    /// Package to install; may be repeated.
    #[arg(long = "package", short = 'p')]
    pub packages: Vec<String>,

    /// Expose the system's site-packages to the environment.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub system_site_packages: Option<bool>,

    /// Tool used to create the environment.
    #[arg(long, value_enum)]
    pub venv_backend: Option<VenvBackendArg>,

    /// Let the sandboxed process write to the virtual environment.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub allow_pip_install: Option<bool>,

    #[command(flatten)]
    pub common: CommonArgs,
}

impl PythonArgs {
    /// The script to run, if one was given.
    pub fn script(&self) -> Option<&str> {
        self.command.first().map(String::as_str)
    }

    /// The arguments to pass to it.
    pub fn args(&self) -> &[String] {
        self.command.get(1..).unwrap_or_default()
    }
}

/// Invoke a host command over the sandbox IPC socket.
///
/// The generated command shims call this; the metadata flags come from the
/// command's declaration on the host, so all argument handling happens here
/// rather than in shell script.
#[derive(Args)]
pub struct IpcArgs {
    /// IPC command name to invoke.
    pub command: String,

    /// Argument name that may be given positionally; repeated, in order.
    #[arg(long = "positional")]
    pub positional: Vec<String>,

    /// Argument name that receives piped standard input.
    #[arg(long = "stdin-arg")]
    pub stdin_arg: Option<String>,

    /// Enable verbose output.
    #[arg(short, long)]
    pub verbose: bool,

    /// Arguments forwarded to the IPC command.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// Arguments shared by the sandboxing subcommands.
///
/// These are deliberately not `global`, because a global option is matched
/// anywhere on the command line: a global `-c` would swallow the `-c` of
/// `heel run /bin/sh -c "..."` instead of leaving it for the program.
#[derive(Args)]
pub struct CommonArgs {
    /// Path to a TOML config file.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Enable verbose output.
    #[arg(short, long)]
    pub verbose: bool,

    /// Network policy.
    #[arg(long, value_enum)]
    pub network: Option<NetworkMode>,

    /// Domain to allow; may be repeated, and supports `*.example.com`.
    #[arg(long = "allow-domain")]
    pub allow_domains: Vec<String>,

    /// Isolation level.
    #[arg(long, value_enum)]
    pub isolation: Option<Isolation>,

    #[command(flatten)]
    pub security: SecurityArgs,

    /// Path the sandbox may read; may be repeated.
    #[arg(long = "readable")]
    pub readable_paths: Vec<PathBuf>,

    /// Path the sandbox may write; may be repeated.
    #[arg(long = "writable")]
    pub writable_paths: Vec<PathBuf>,

    /// Path the sandbox may execute; may be repeated.
    #[arg(long = "executable")]
    pub executable_paths: Vec<PathBuf>,

    /// Maximum address space, in bytes.
    #[arg(long)]
    pub max_memory: Option<u64>,

    /// Maximum CPU time, in seconds.
    #[arg(long)]
    pub max_cpu_time: Option<u64>,

    /// Maximum size of a file the sandbox may create, in bytes.
    #[arg(long)]
    pub max_file_size: Option<u64>,

    /// Maximum number of processes.
    #[arg(long)]
    pub max_processes: Option<u64>,

    /// Working directory for the sandbox.
    #[arg(long)]
    pub working_dir: Option<PathBuf>,

    /// Keep a generated working directory after the sandbox exits.
    #[arg(long)]
    pub keep_working_dir: bool,

    /// Host environment variable to forward; may be repeated.
    #[arg(long = "env-passthrough")]
    pub env_passthroughs: Vec<String>,

    /// Environment variable to set as `KEY=VALUE`; may be repeated.
    #[arg(long = "env", short = 'e')]
    pub envs: Vec<String>,
}

/// Declare the security toggles once, and derive both the command-line flags
/// and the conversion into the library's override type from that one list.
///
/// Each flag takes an optional value: `--protect-credentials` enables the
/// protection and `--protect-credentials=false` disables it, so a config file
/// setting can be overridden in either direction.
macro_rules! security_args {
    ($( $(#[$doc:meta])* $name:ident ),* $(,)?) => {
        #[derive(Args, Debug, Default)]
        pub struct SecurityArgs {
            $(
                $(#[$doc])*
                #[arg(
                    long,
                    num_args = 0..=1,
                    require_equals = true,
                    default_missing_value = "true"
                )]
                pub $name: Option<bool>,
            )*
        }

        impl From<&SecurityArgs> for SecurityOverrides {
            fn from(args: &SecurityArgs) -> Self {
                Self { $( $name: args.$name, )* }
            }
        }
    };
}

security_args! {
    /// Protect user home directories.
    protect_user_home,
    /// Let macOS prompt for TCC-protected folders instead of denying them.
    allow_tcc_prompts,
    /// Protect SSH and GPG credentials.
    protect_credentials,
    /// Protect cloud provider configuration.
    protect_cloud_config,
    /// Protect browser data.
    protect_browser_data,
    /// Protect the system keychain.
    protect_keychain,
    /// Protect shell history.
    protect_shell_history,
    /// Protect package manager credentials.
    protect_package_credentials,
    /// Allow GPU access.
    allow_gpu,
    /// Allow NPU / Neural Engine access.
    allow_npu,
    /// Allow general hardware access.
    allow_hardware,
}

/// How much of the host the sandbox can see.
#[derive(ValueEnum, Clone, Copy, Default, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Isolation {
    /// Only the sandbox working directory is readable or writable.
    Strict,
    /// The working directory is writable; the rest of the system is readable.
    #[default]
    Default,
    /// The whole filesystem is readable and writable.
    Permissive,
}

/// Which network policy to apply.
#[derive(ValueEnum, Clone, Copy, Default, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    /// Deny all network access.
    #[default]
    Deny,
    /// Allow all network access.
    Allow,
    /// Allow only the listed domains.
    AllowList,
}

/// Tool used to create a Python virtual environment.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VenvBackendArg {
    /// Use `uv` when installed, `python -m venv` otherwise.
    Auto,
    /// Require `uv`.
    Uv,
    /// Use `python -m venv`.
    Python,
}

impl From<VenvBackendArg> for heel::VenvBackend {
    fn from(arg: VenvBackendArg) -> Self {
        match arg {
            VenvBackendArg::Auto => Self::Auto,
            VenvBackendArg::Uv => Self::Uv,
            VenvBackendArg::Python => Self::Python,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::path::Path;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn security_flags_default_to_enabling() {
        let cli = Cli::try_parse_from(["heel", "run", "--protect-credentials", "true"]);
        // `require_equals` means the bare flag takes no separate value, so the
        // value above is parsed as the program's argument, not the flag's.
        let cli = cli.expect("parses");
        let Commands::Run(args) = cli.command else {
            panic!("expected run");
        };
        assert_eq!(args.common.security.protect_credentials, Some(true));
    }

    #[test]
    fn security_flags_accept_an_explicit_value() {
        let cli = Cli::try_parse_from(["heel", "run", "--protect-credentials=false", "echo"])
            .expect("parses");
        let Commands::Run(args) = cli.command else {
            panic!("expected run");
        };
        assert_eq!(args.common.security.protect_credentials, Some(false));
        assert_eq!(args.program(), "echo");
    }

    #[test]
    fn unset_security_flags_stay_none() {
        let cli = Cli::try_parse_from(["heel", "run", "echo"]).expect("parses");
        let Commands::Run(args) = cli.command else {
            panic!("expected run");
        };
        let overrides = SecurityOverrides::from(&args.common.security);
        assert_eq!(overrides, SecurityOverrides::default());
    }

    #[test]
    fn network_mode_is_none_when_unset() {
        let cli = Cli::try_parse_from(["heel", "run", "echo"]).expect("parses");
        let Commands::Run(args) = cli.command else {
            panic!("expected run");
        };
        assert_eq!(args.common.network, None);
    }

    #[test]
    fn explicit_deny_is_distinguishable_from_unset() {
        let cli =
            Cli::try_parse_from(["heel", "run", "--network", "deny", "echo"]).expect("parses");
        let Commands::Run(args) = cli.command else {
            panic!("expected run");
        };
        assert_eq!(args.common.network, Some(NetworkMode::Deny));
    }

    #[test]
    fn program_flags_are_not_stolen_by_the_cli() {
        // `-c` belongs to the program here, not to `--config`.
        let cli = Cli::try_parse_from(["heel", "run", "/bin/sh", "-c", "exit 7"]).expect("parses");
        let Commands::Run(args) = cli.command else {
            panic!("expected run");
        };

        assert_eq!(args.program(), "/bin/sh");
        assert_eq!(args.args(), ["-c", "exit 7"]);
        assert_eq!(args.common.config, None);
    }

    #[test]
    fn sandbox_flags_still_parse_before_the_program() {
        let cli = Cli::try_parse_from([
            "heel",
            "run",
            "--config",
            "heel.toml",
            "--isolation",
            "strict",
            "/bin/sh",
            "-c",
            "x",
        ])
        .expect("parses");
        let Commands::Run(args) = cli.command else {
            panic!("expected run");
        };

        assert_eq!(args.common.config.as_deref(), Some(Path::new("heel.toml")));
        assert_eq!(args.common.isolation, Some(Isolation::Strict));
        assert_eq!(args.program(), "/bin/sh");
        assert_eq!(args.args(), ["-c", "x"]);
    }

    #[test]
    fn ipc_metadata_is_separated_from_forwarded_arguments() {
        let cli = Cli::try_parse_from([
            "heel",
            "ipc",
            "search",
            "--positional",
            "query",
            "--stdin-arg",
            "input",
            "--",
            "rust",
            "--limit",
            "3",
        ])
        .expect("parses");
        let Commands::Ipc(args) = cli.command else {
            panic!("expected ipc");
        };

        assert_eq!(args.command, "search");
        assert_eq!(args.positional, ["query"]);
        assert_eq!(args.stdin_arg.as_deref(), Some("input"));
        assert_eq!(args.args, ["rust", "--limit", "3"]);
    }
}
