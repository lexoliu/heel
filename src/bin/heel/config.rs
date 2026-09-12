//! Configuration merging: file first, command line on top.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use heel::{Access, Grant, ResourceLimits, SecurityConfig, SecurityOverrides, VenvBackend};
use serde::Deserialize;

use crate::cli::{CommonArgs, Isolation, NetworkMode, PythonArgs, VenvBackendArg};
use crate::error::{CliError, CliResult};

/// The TOML config file.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct FileConfig {
    /// Network policy.
    pub network: Option<NetworkMode>,
    /// Domains to allow under the `allow-list` policy.
    pub allow_domains: Vec<String>,
    /// File the network decisions of each run are appended to.
    pub audit_log: Option<PathBuf>,
    /// Isolation level.
    pub isolation: Option<Isolation>,
    /// Security toggles layered onto the isolation level's preset.
    pub security: SecurityOverrides,
    /// Paths the sandbox may use, each mapped to its access mode.
    pub grants: BTreeMap<PathBuf, Access>,
    /// Resource limits.
    pub limits: LimitsSection,
    /// Working directory settings.
    pub workdir: WorkdirSection,
    /// Environment settings.
    pub env: EnvSection,
    /// Python settings.
    pub python: PythonSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct LimitsSection {
    pub max_memory: Option<u64>,
    pub max_cpu_time: Option<u64>,
    pub max_file_size: Option<u64>,
    pub max_processes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct WorkdirSection {
    pub path: Option<PathBuf>,
    pub keep: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct EnvSection {
    pub passthrough: Vec<String>,
    pub set: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct PythonSection {
    pub venv: Option<PathBuf>,
    pub interpreter: Option<PathBuf>,
    pub packages: Vec<String>,
    pub system_site_packages: Option<bool>,
    pub venv_backend: Option<VenvBackendArg>,
    pub allow_pip_install: Option<bool>,
}

/// The effective configuration for one invocation.
#[derive(Debug)]
pub struct MergedConfig {
    pub network_mode: NetworkMode,
    pub allow_domains: Vec<String>,
    pub audit_log: Option<PathBuf>,
    pub isolation: Isolation,
    pub security: SecurityConfig,
    pub grants: Vec<Grant>,
    pub limits: ResourceLimits,
    pub working_dir: Option<PathBuf>,
    pub keep_working_dir: bool,
    pub env_passthroughs: Vec<String>,
    pub env_set: BTreeMap<String, String>,
    pub python: MergedPythonConfig,
}

#[derive(Debug)]
pub struct MergedPythonConfig {
    pub venv: Option<PathBuf>,
    pub interpreter: Option<PathBuf>,
    pub packages: Vec<String>,
    pub system_site_packages: bool,
    pub backend: VenvBackend,
    pub allow_pip_install: bool,
}

/// Read a config file, or return the defaults when none is given.
pub fn load_config(path: Option<&Path>) -> CliResult<FileConfig> {
    let Some(path) = path else {
        return Ok(FileConfig::default());
    };

    let content = std::fs::read_to_string(path).map_err(|source| CliError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;

    toml::from_str(&content).map_err(|source| CliError::ParseConfig {
        path: path.to_path_buf(),
        source: Box::new(source),
    })
}

/// Merge the file config with command-line arguments.
///
/// Scalar settings take the command-line value when one was given, and the file
/// value otherwise; list settings are concatenated, file entries first.
pub fn merge_config(file: FileConfig, cli: &CommonArgs) -> CliResult<MergedConfig> {
    let isolation = cli.isolation.or(file.isolation).unwrap_or_default();

    // The isolation level chooses the preset; explicit toggles refine it, with
    // the command line winning over the file.
    let security = isolation
        .security_preset()
        .with(&file.security)
        .with(&SecurityOverrides::from(&cli.security));

    let mut env_set = file.env.set;
    for entry in &cli.envs {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| CliError::InvalidEnvFormat {
                value: entry.clone(),
            })?;
        env_set.insert(key.to_string(), value.to_string());
    }

    let network_mode = cli.network.or(file.network).unwrap_or_default();
    let allow_domains = concat(file.allow_domains, &cli.allow_domains);
    if network_mode == NetworkMode::AllowList && allow_domains.is_empty() {
        return Err(CliError::MissingAllowDomains);
    }

    // An audit log records what the proxy decided, and a deny-all policy runs
    // no proxy: the kernel refuses every connection before a policy sees it, so
    // the log would stay empty rather than recording denials.
    let audit_log = cli.audit_log.clone().or(file.audit_log);
    if audit_log.is_some() && network_mode == NetworkMode::Deny {
        return Err(CliError::AuditLogWithoutProxy);
    }

    Ok(MergedConfig {
        network_mode,
        allow_domains,
        audit_log,
        isolation,
        security,
        grants: merge_grants(file.grants, cli),
        limits: merge_limits(&file.limits, cli),
        working_dir: cli.working_dir.clone().or(file.workdir.path),
        keep_working_dir: cli.keep_working_dir || file.workdir.keep,
        env_passthroughs: concat(file.env.passthrough, &cli.env_passthroughs),
        env_set,
        python: MergedPythonConfig {
            venv: file.python.venv,
            interpreter: file.python.interpreter,
            packages: file.python.packages,
            system_site_packages: file.python.system_site_packages.unwrap_or(true),
            backend: file
                .python
                .venv_backend
                .map_or(VenvBackend::Auto, Into::into),
            allow_pip_install: file.python.allow_pip_install.unwrap_or(false),
        },
    })
}

/// Layer the `python` subcommand's own arguments onto the merged config.
pub fn merge_python_args(config: &mut MergedConfig, args: &PythonArgs) {
    let python = &mut config.python;

    if args.venv.is_some() {
        python.venv = args.venv.clone();
    }
    if args.python.is_some() {
        python.interpreter = args.python.clone();
    }
    python.packages.extend(args.packages.iter().cloned());
    if let Some(value) = args.system_site_packages {
        python.system_site_packages = value;
    }
    if let Some(backend) = args.venv_backend {
        python.backend = backend.into();
    }
    if let Some(value) = args.allow_pip_install {
        python.allow_pip_install = value;
    }
}

impl Isolation {
    /// The security preset this isolation level starts from.
    pub fn security_preset(self) -> SecurityConfig {
        match self {
            Self::Strict | Self::Default => SecurityConfig::strict(),
            Self::Permissive => SecurityConfig::permissive(),
        }
    }

    /// Whether reads outside the working directory and allow list are denied.
    pub fn filesystem_strict(self) -> bool {
        matches!(self, Self::Strict)
    }

    /// Whether the whole filesystem is writable.
    pub fn writable_file_system(self) -> bool {
        matches!(self, Self::Permissive)
    }
}

/// Append command-line entries to file entries.
fn concat<T: Clone>(mut file: Vec<T>, cli: &[T]) -> Vec<T> {
    file.extend_from_slice(cli);
    file
}

/// Combine the file's grants with the command line's.
///
/// A path granted more than once keeps the union of its modes, so
/// `--writable p --executable p` and `--grant p=rwx` describe the same sandbox,
/// and a file that makes a path readable plus a `--grant p=rw` widens it rather
/// than one silently replacing the other. Ordering by path keeps the resulting
/// profile stable across runs.
fn merge_grants(file: BTreeMap<PathBuf, Access>, cli: &CommonArgs) -> Vec<Grant> {
    let mut grants = file;

    let from_flags = cli
        .readable
        .iter()
        .map(|path| (path.clone(), Access::READ))
        .chain(
            cli.writable
                .iter()
                .map(|path| (path.clone(), Access::WRITE)),
        )
        .chain(
            cli.executable
                .iter()
                .map(|path| (path.clone(), Access::EXEC)),
        )
        .chain(
            cli.grants
                .iter()
                .map(|grant| (grant.path.clone(), grant.access)),
        );

    for (path, access) in from_flags {
        *grants.entry(path).or_insert(access) |= access;
    }

    grants
        .into_iter()
        .map(|(path, access)| Grant::new(path, access))
        .collect()
}

fn merge_limits(file: &LimitsSection, cli: &CommonArgs) -> ResourceLimits {
    let mut builder = ResourceLimits::builder();

    if let Some(value) = cli.max_memory.or(file.max_memory) {
        builder = builder.max_memory_bytes(value);
    }
    if let Some(value) = cli.max_cpu_time.or(file.max_cpu_time) {
        builder = builder.max_cpu_time_secs(value);
    }
    if let Some(value) = cli.max_file_size.or(file.max_file_size) {
        builder = builder.max_file_size_bytes(value);
    }
    if let Some(value) = cli.max_processes.or(file.max_processes) {
        builder = builder.max_processes(value);
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use clap::Parser;

    /// Parse the common arguments of a `heel run` invocation.
    fn common_args(args: &[&str]) -> CommonArgs {
        let argv: Vec<&str> = ["heel", "run"]
            .iter()
            .copied()
            .chain(args.iter().copied())
            .chain(["/bin/echo"])
            .collect();
        let Commands::Run(run) = Cli::try_parse_from(argv).expect("parses").command else {
            panic!("expected run");
        };
        run.common
    }

    #[test]
    fn file_settings_apply_when_the_command_line_is_silent() {
        let file: FileConfig = toml::from_str("network = \"allow\"").expect("parses");
        let merged = merge_config(file, &common_args(&[])).expect("merges");
        assert_eq!(merged.network_mode, NetworkMode::Allow);
    }

    #[test]
    fn the_command_line_can_restore_the_default_network_mode() {
        // An explicit `--network deny` must override a permissive file setting,
        // which a "differs from the default" check would silently ignore.
        let file: FileConfig = toml::from_str("network = \"allow\"").expect("parses");
        let merged = merge_config(file, &common_args(&["--network", "deny"])).expect("merges");
        assert_eq!(merged.network_mode, NetworkMode::Deny);
    }

    #[test]
    fn allow_list_without_domains_is_rejected() {
        let error = merge_config(
            FileConfig::default(),
            &common_args(&["--network", "allow-list"]),
        )
        .expect_err("must fail");
        assert!(matches!(error, CliError::MissingAllowDomains));
    }

    #[test]
    fn the_audit_log_prefers_the_command_line_over_the_file() {
        let file: FileConfig =
            toml::from_str("network = \"allow\"\naudit-log = \"/var/log/from-file.jsonl\"")
                .expect("parses");
        let merged = merge_config(file, &common_args(&["--audit-log", "/tmp/from-cli.jsonl"]))
            .expect("merges");

        assert_eq!(
            merged.audit_log.as_deref(),
            Some(Path::new("/tmp/from-cli.jsonl"))
        );
    }

    #[test]
    fn the_audit_log_can_come_from_the_file_alone() {
        let file: FileConfig =
            toml::from_str("network = \"allow\"\naudit-log = \"/var/log/heel.jsonl\"")
                .expect("parses");
        let merged = merge_config(file, &common_args(&[])).expect("merges");

        assert_eq!(
            merged.audit_log.as_deref(),
            Some(Path::new("/var/log/heel.jsonl"))
        );
    }

    #[test]
    fn an_audit_log_without_a_proxy_is_rejected() {
        // Deny-all is the default, and it denies in the kernel without ever
        // consulting a policy, so an audit log would record nothing at all.
        let error = merge_config(
            FileConfig::default(),
            &common_args(&["--audit-log", "/tmp/heel.jsonl"]),
        )
        .expect_err("must fail");
        assert!(matches!(error, CliError::AuditLogWithoutProxy));

        let file: FileConfig =
            toml::from_str("audit-log = \"/tmp/heel.jsonl\"\nnetwork = \"deny\"").expect("parses");
        let error = merge_config(file, &common_args(&[])).expect_err("must fail");
        assert!(matches!(error, CliError::AuditLogWithoutProxy));
    }

    #[test]
    fn security_overrides_layer_file_then_command_line() {
        let file: FileConfig =
            toml::from_str("[security]\nprotect-credentials = false\nallow-gpu = false")
                .expect("parses");
        let merged = merge_config(file, &common_args(&["--allow-gpu=true"])).expect("merges");

        // The file disabled both; the command line re-enabled one of them.
        assert!(!merged.security.protect_credentials());
        assert!(merged.security.allow_gpu());
    }

    #[test]
    fn isolation_levels_are_distinct() {
        assert!(Isolation::Strict.filesystem_strict());
        assert!(!Isolation::Default.filesystem_strict());
        assert!(!Isolation::Permissive.filesystem_strict());

        assert!(!Isolation::Strict.writable_file_system());
        assert!(!Isolation::Default.writable_file_system());
        assert!(Isolation::Permissive.writable_file_system());

        assert!(Isolation::Default.security_preset().protect_user_home());
        assert!(!Isolation::Permissive.security_preset().protect_user_home());
    }

    #[test]
    fn grants_and_domains_concatenate() {
        let file: FileConfig =
            toml::from_str("allow-domains = [\"a.example\"]\n[grants]\n\"/etc\" = \"r\"")
                .expect("parses");
        let merged = merge_config(
            file,
            &common_args(&[
                "--network",
                "allow-list",
                "--allow-domain",
                "b.example",
                "--readable",
                "/usr",
            ]),
        )
        .expect("merges");

        assert_eq!(merged.allow_domains, ["a.example", "b.example"]);
        assert_eq!(
            merged.grants,
            [
                Grant::new("/etc", Access::READ),
                Grant::new("/usr", Access::READ)
            ]
        );
    }

    #[test]
    fn the_sugar_flags_and_a_grant_mode_describe_the_same_sandbox() {
        // Both spellings have to reach the backends as one grant carrying both
        // rights: two grants for the same path would leave the outcome to
        // whichever rule a backend happens to emit last.
        let spelled_out = merge_config(
            FileConfig::default(),
            &common_args(&["--writable", "/opt/cache", "--executable", "/opt/cache"]),
        )
        .expect("merges");
        let one_mode = merge_config(
            FileConfig::default(),
            &common_args(&["--grant", "/opt/cache=rwx"]),
        )
        .expect("merges");

        assert_eq!(
            spelled_out.grants,
            [Grant::new("/opt/cache", Access::WRITE | Access::EXEC)]
        );
        assert_eq!(spelled_out.grants, one_mode.grants);
    }

    #[test]
    fn a_file_grant_and_a_command_line_grant_for_one_path_are_unioned() {
        let file: FileConfig = toml::from_str("[grants]\n\"/opt/cache\" = \"rw\"").expect("parses");
        let merged =
            merge_config(file, &common_args(&["--grant", "/opt/cache=rx"])).expect("merges");

        assert_eq!(
            merged.grants,
            [Grant::new("/opt/cache", Access::WRITE | Access::EXEC)]
        );
    }

    #[test]
    fn an_unparsable_grant_mode_in_the_file_is_an_error() {
        let error = toml::from_str::<FileConfig>("[grants]\n\"/opt\" = \"rq\"").unwrap_err();
        assert!(error.to_string().contains("unknown access mode"), "{error}");
    }

    #[test]
    fn limits_prefer_the_command_line() {
        let file: FileConfig =
            toml::from_str("[limits]\nmax-memory = 1\nmax-cpu-time = 2").expect("parses");
        let merged = merge_config(file, &common_args(&["--max-memory", "99"])).expect("merges");

        assert_eq!(merged.limits.max_memory_bytes(), Some(99));
        assert_eq!(merged.limits.max_cpu_time_secs(), Some(2));
    }

    #[test]
    fn malformed_env_assignments_are_rejected() {
        let error = merge_config(FileConfig::default(), &common_args(&["-e", "NOEQUALS"]))
            .expect_err("must fail");
        assert!(matches!(error, CliError::InvalidEnvFormat { .. }));
    }

    #[test]
    fn unknown_config_keys_are_rejected() {
        // A mistyped key must be an error rather than a setting silently
        // ignored, which is what `deny_unknown_fields` buys.
        let error = toml::from_str::<FileConfig>("not_a_real_setting = \"allow\"").unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
}
