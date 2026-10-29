//! Configuration merging: file first, command line on top.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use heel::{
    Access, CpuPriority, Grant, IoPriority, NiceLevel, PathRequest, ProcessPriority, ResolvedPath,
    ResourceLimits, SecurityConfig, SecurityOverrides, VenvBackend, VenvConfig,
};
use serde::Deserialize;

use crate::cli::{
    CommonArgs, GrantArg, IoPriorityArg, Isolation, NetworkMode, PythonArgs, VenvBackendArg,
};
use crate::error::{CliError, CliResult};

/// The TOML config file.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct FileConfig {
    /// Trusted TCP IPC peer.
    pub ipc_endpoint: Option<String>,
    /// IPC request deadline in seconds.
    pub ipc_timeout_seconds: Option<u64>,
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
    /// Scheduling priority.
    pub priority: PrioritySection,
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
pub struct PrioritySection {
    /// Steps below the invoking process's CPU priority, from 1 to 19.
    pub nice: Option<u8>,
    /// Disk I/O priority: `normal`, `utility` or `background`.
    pub io: Option<IoPriorityArg>,
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
    pub ipc_endpoint: Option<String>,
    pub ipc_timeout: std::time::Duration,
    pub network_mode: NetworkMode,
    pub allow_domains: Vec<String>,
    pub audit_log: Option<PathBuf>,
    pub isolation: Isolation,
    pub security: SecurityConfig,
    pub grants: Vec<GrantArg>,
    pub limits: ResourceLimits,
    pub priority: ProcessPriority,
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
        ipc_endpoint: cli.ipc_endpoint.clone().or(file.ipc_endpoint),
        ipc_timeout: cli
            .ipc_timeout
            .or(file.ipc_timeout_seconds.map(std::time::Duration::from_secs))
            .unwrap_or(std::time::Duration::from_secs(30)),
        network_mode,
        allow_domains,
        audit_log,
        isolation,
        security,
        grants: merge_grants(file.grants, cli),
        limits: merge_limits(&file.limits, cli),
        priority: merge_priority(&file.priority, cli)?,
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

/// Resolve the paths a configuration names.
impl MergedConfig {
    /// The paths this configuration names, as the user wrote them.
    ///
    /// When Python is configured the environment's path is always set, to the
    /// library default when the user gave none.
    pub fn path_spec(&self) -> PathSpec {
        let python = &self.python;
        let venv = (python.venv.is_some() || !python.packages.is_empty()).then(|| {
            python
                .venv
                .clone()
                .unwrap_or_else(|| VenvConfig::default().path().to_path_buf())
        });
        PathSpec {
            grants: self.grants.clone(),
            working_dir: self.working_dir.clone(),
            venv,
            venv_writable: python.allow_pip_install,
        }
    }

    /// Resolve every path the user wrote, once, for this run; see
    /// [`PathSpec::resolve`]. The filesystem work runs off the async thread.
    pub async fn resolve_paths(&self) -> CliResult<ResolvedPaths> {
        let spec = self.path_spec();
        blocking::unblock(move || spec.resolve()).await
    }
}

/// The paths of one invocation, spelled as the user wrote them.
#[derive(Debug)]
pub struct PathSpec {
    grants: Vec<GrantArg>,
    working_dir: Option<PathBuf>,
    venv: Option<PathBuf>,
    venv_writable: bool,
}

/// The paths of one invocation, resolved.
#[derive(Debug, Default)]
pub struct ResolvedPaths {
    /// The grants, one per resolved path with the union of its modes.
    pub grants: Vec<Grant>,
    /// The working directory, when the user named one.
    pub working_dir: Option<ResolvedPath>,
    /// The virtual environment, when Python is configured.
    pub venv: Option<ResolvedPath>,
}

/// What a path is for, carried through resolution so each result finds its
/// place without being matched back by position.
enum Role {
    Grant(Access),
    WorkingDir,
    Venv,
}

impl PathSpec {
    /// Resolve every path the user wrote, once, for this run.
    ///
    /// The library does the resolving (see [`heel::resolve_paths`]): a spelling such
    /// as `/tmp/x` or a relative path becomes the path the sandbox is built
    /// from. Links the user's own spelling crosses are followed, but a link
    /// inside a directory this configuration makes writable, or a writable path
    /// that is itself a link, is refused: a sandbox of an earlier run may have
    /// planted it, and following it would move a grant to the link's target.
    /// Two spellings of one path merge into one grant.
    ///
    /// The working directory and the virtual environment may not exist yet.
    pub fn resolve(self) -> CliResult<ResolvedPaths> {
        let requests = self
            .grants
            .into_iter()
            .map(|grant| {
                (
                    request(grant.path, grant.access.can_write()),
                    Role::Grant(grant.access),
                )
            })
            .chain(self.working_dir.into_iter().map(|dir| {
                (
                    PathRequest::writable(dir).allow_missing_tail(),
                    Role::WorkingDir,
                )
            }))
            .chain(self.venv.into_iter().map(|path| {
                (
                    request(path, self.venv_writable).allow_missing_tail(),
                    Role::Venv,
                )
            }));

        let mut resolved = ResolvedPaths::default();
        let mut grants = BTreeMap::<ResolvedPath, Access>::new();
        for (path, role) in heel::resolve_paths(requests)? {
            match role {
                Role::Grant(access) => *grants.entry(path).or_insert(access) |= access,
                Role::WorkingDir => resolved.working_dir = Some(path),
                Role::Venv => resolved.venv = Some(path),
            }
        }
        resolved.grants = grants
            .into_iter()
            .map(|(path, access)| Grant::new(path, access))
            .collect();
        Ok(resolved)
    }
}

/// A request for `path`, writable or not.
fn request(path: PathBuf, writable: bool) -> PathRequest {
    if writable {
        PathRequest::writable(path)
    } else {
        PathRequest::readable(path)
    }
}

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
fn merge_grants(file: BTreeMap<PathBuf, Access>, cli: &CommonArgs) -> Vec<GrantArg> {
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
        .map(|(path, access)| GrantArg { path, access })
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

/// Combine the file's scheduling priority with the command line's.
///
/// A nice level outside `1..=19` is rejected here rather than clamped: the
/// level counts steps below the invoking process, so a value that steps
/// nowhere or upwards is a mistake about what the setting does.
fn merge_priority(file: &PrioritySection, cli: &CommonArgs) -> CliResult<ProcessPriority> {
    let cpu = match cli.nice.or(file.nice) {
        Some(level) => CpuPriority::Nice(NiceLevel::new(level)?),
        None => CpuPriority::Normal,
    };
    let io = cli
        .io_priority
        .or(file.io)
        .map_or(IoPriority::Normal, Into::into);

    Ok(ProcessPriority::new(cpu, io))
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

    /// A grant as the user spelled it.
    fn spec(path: &str, access: Access) -> GrantArg {
        GrantArg {
            path: PathBuf::from(path),
            access,
        }
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
            [spec("/etc", Access::READ), spec("/usr", Access::READ)]
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
            [spec("/opt/cache", Access::WRITE | Access::EXEC)]
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
            [spec("/opt/cache", Access::WRITE | Access::EXEC)]
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
    fn the_priority_prefers_the_command_line() {
        let file: FileConfig =
            toml::from_str("[priority]\nnice = 3\nio = \"utility\"").expect("parses");
        let merged = merge_config(file, &common_args(&["--nice", "12"])).expect("merges");

        assert_eq!(
            merged.priority,
            ProcessPriority::new(
                CpuPriority::Nice(NiceLevel::new(12).unwrap()),
                IoPriority::Utility,
            )
        );
    }

    #[test]
    fn an_unconfigured_priority_lowers_nothing() {
        let merged = merge_config(FileConfig::default(), &common_args(&[])).expect("merges");
        assert!(merged.priority.is_normal());
    }

    #[test]
    fn the_io_priority_comes_from_either_source() {
        let merged = merge_config(
            FileConfig::default(),
            &common_args(&["--io-priority", "background"]),
        )
        .expect("merges");
        assert_eq!(merged.priority.io(), IoPriority::Background);

        let file: FileConfig = toml::from_str("[priority]\nio = \"background\"").expect("parses");
        let merged = merge_config(file, &common_args(&[])).expect("merges");
        assert_eq!(merged.priority.io(), IoPriority::Background);
    }

    #[test]
    fn a_nice_level_that_would_raise_priority_is_rejected() {
        // Zero is the default priority, so asking for it is a mistake about
        // what the flag does rather than a request to be clamped.
        let error = merge_config(FileConfig::default(), &common_args(&["--nice", "0"]))
            .expect_err("must fail");
        assert!(matches!(error, CliError::InvalidNiceLevel(_)), "{error}");

        let file: FileConfig = toml::from_str("[priority]\nnice = 20").expect("parses");
        let error = merge_config(file, &common_args(&[])).expect_err("must fail");
        assert!(matches!(error, CliError::InvalidNiceLevel(_)), "{error}");
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

    /// A directory at its resolved path.
    #[cfg(unix)]
    fn resolved_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dunce::canonicalize(dir.path()).expect("resolves");
        (dir, path)
    }

    #[cfg(unix)]
    fn resolve(args: &[&str]) -> CliResult<ResolvedPaths> {
        merge_config(FileConfig::default(), &common_args(args))?
            .path_spec()
            .resolve()
    }

    #[cfg(unix)]
    fn resolved(path: impl AsRef<Path>) -> ResolvedPath {
        ResolvedPath::new(path).expect("the path is resolved")
    }

    /// `root/alias -> root/real` and the directory `root/real/granted`.
    #[cfg(unix)]
    fn aliased_grant(root: &Path) -> (PathBuf, PathBuf) {
        let real = root.join("real");
        std::fs::create_dir_all(real.join("granted")).expect("creates");
        std::os::unix::fs::symlink(&real, root.join("alias")).expect("links");
        (root.join("alias/granted"), real.join("granted"))
    }

    /// What a sandbox does between two runs.
    #[cfg(unix)]
    fn swap_for_link(directory: &Path, target: &Path) {
        std::fs::remove_dir_all(directory).expect("removes");
        std::os::unix::fs::symlink(target, directory).expect("links");
    }

    #[cfg(unix)]
    #[test]
    fn spellings_of_one_grant_resolve_and_merge() {
        let (_guard, root) = resolved_dir();
        let cache = root.join("cache");
        std::fs::create_dir(&cache).expect("creates");
        std::os::unix::fs::symlink(&cache, root.join("alias")).expect("links");
        let (cache_arg, alias_arg) = (
            cache.to_str().expect("utf-8"),
            root.join("alias").to_string_lossy().into_owned(),
        );

        let paths = resolve(&["--readable", &alias_arg, "--executable", cache_arg]).expect("ok");

        assert_eq!(
            paths.grants,
            [Grant::new(resolved(&cache), Access::READ | Access::EXEC)]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_above_a_writable_grant_is_followed() {
        let (_guard, root) = resolved_dir();
        let (spelled, real) = aliased_grant(&root);

        let paths = resolve(&["--writable", spelled.to_str().expect("utf-8")])
            .expect("a link outside writable territory resolves");

        assert_eq!(paths.grants, [Grant::new(resolved(real), Access::WRITE)]);
    }

    #[cfg(unix)]
    #[test]
    fn a_granted_directory_a_sandbox_replaced_with_a_link_is_refused() {
        let (_guard, root) = resolved_dir();
        let (granted, target) = (root.join("granted"), root.join("target"));
        std::fs::create_dir_all(&target).expect("creates");
        std::os::unix::fs::symlink(&target, &granted).expect("links");

        let error = resolve(&["--writable", granted.to_str().expect("utf-8")])
            .expect_err("a planted link must be refused");

        assert!(
            matches!(&error, CliError::Sandbox(heel::Error::GrantRedirected { path, .. }) if *path == granted),
            "{error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_grant_spelled_through_a_link_above_it_and_replaced_is_refused() {
        // `/tmp/...` on macOS: the spelling crosses a link the user wrote, so
        // the planted link sits at the resolved spelling of the grant instead.
        let (_guard, root) = resolved_dir();
        let (spelled, real) = aliased_grant(&root);
        let target = root.join("target");
        std::fs::create_dir(&target).expect("creates");
        let argument = spelled.to_str().expect("utf-8");
        resolve(&["--writable", argument]).expect("an unchanged grant resolves");
        swap_for_link(&real, &target);

        let error = resolve(&["--writable", argument]).expect_err("planted");

        assert!(
            matches!(&error, CliError::Sandbox(heel::Error::GrantRedirected { path, .. }) if *path == spelled),
            "{error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_grant_names_itself() {
        let (_guard, root) = resolved_dir();
        let missing = root.join("absent");

        let error = resolve(&["--readable", missing.to_str().expect("utf-8")])
            .expect_err("a missing path cannot be granted");

        assert!(
            matches!(&error, CliError::Sandbox(heel::Error::Path { path, .. }) if *path == missing),
            "{error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_working_directory_and_environment_may_not_exist_yet() {
        let (_guard, root) = resolved_dir();
        let real = root.join("real");
        std::fs::create_dir(&real).expect("creates");
        std::os::unix::fs::symlink(&real, root.join("link")).expect("links");
        let mut file = FileConfig::default();
        file.python.packages = vec!["numpy".into()];
        file.workdir.path = Some(root.join("link/work"));
        file.python.venv = Some(root.join("link/venv"));
        let merged = merge_config(file, &common_args(&[])).expect("merges");

        let paths = merged.path_spec().resolve().expect("resolves");

        assert_eq!(
            paths.working_dir.as_ref().map(ResolvedPath::as_path),
            Some(real.join("work").as_path())
        );
        assert_eq!(
            paths.venv.as_ref().map(ResolvedPath::as_path),
            Some(real.join("venv").as_path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_default_environment_path_is_set_and_absolute() {
        let mut file = FileConfig::default();
        file.python.packages = vec!["numpy".into()];
        let merged = merge_config(file, &common_args(&[])).expect("merges");

        let paths = merged.path_spec().resolve().expect("resolves");

        let venv = paths.venv.expect("named");
        assert!(
            venv.as_path().is_absolute() && venv.as_path().ends_with(".sandbox-venv"),
            "{venv:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_writable_environment_replaced_with_a_link_is_refused() {
        let (_guard, root) = resolved_dir();
        let (venv, target) = (root.join("venv"), root.join("target"));
        std::fs::create_dir_all(&target).expect("creates");
        std::os::unix::fs::symlink(&target, &venv).expect("links");
        let mut file = FileConfig::default();
        file.python.venv = Some(venv.clone());
        file.python.allow_pip_install = Some(true);
        let merged = merge_config(file, &common_args(&[])).expect("merges");

        let error = merged.path_spec().resolve().expect_err("planted");

        assert!(
            matches!(
                &error,
                CliError::Sandbox(heel::Error::GrantRedirected { .. })
            ),
            "{error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_working_directory_replaced_with_a_link_is_refused() {
        let (_guard, root) = resolved_dir();
        let (work, target) = (root.join("work"), root.join("target"));
        std::fs::create_dir_all(&target).expect("creates");
        std::os::unix::fs::symlink(&target, &work).expect("links");
        let mut file = FileConfig::default();
        file.workdir.path = Some(work);
        let merged = merge_config(file, &common_args(&[])).expect("merges");

        let error = merged.path_spec().resolve().expect_err("planted");

        assert!(
            matches!(
                &error,
                CliError::Sandbox(heel::Error::GrantRedirected { .. })
            ),
            "{error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_working_directory_spelled_through_a_link_above_it_and_replaced_is_refused() {
        let (_guard, root) = resolved_dir();
        let (spelled, real) = aliased_grant(&root);
        let target = root.join("target");
        std::fs::create_dir(&target).expect("creates");
        swap_for_link(&real, &target);
        let mut file = FileConfig::default();
        file.workdir.path = Some(spelled);
        let merged = merge_config(file, &common_args(&[])).expect("merges");

        let error = merged.path_spec().resolve().expect_err("planted");

        assert!(
            matches!(
                &error,
                CliError::Sandbox(heel::Error::GrantRedirected { .. })
            ),
            "{error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_writable_environment_spelled_through_a_link_above_it_and_replaced_is_refused() {
        let (_guard, root) = resolved_dir();
        let (spelled, real) = aliased_grant(&root);
        let target = root.join("target");
        std::fs::create_dir(&target).expect("creates");
        swap_for_link(&real, &target);
        let mut file = FileConfig::default();
        file.python.venv = Some(spelled);
        file.python.allow_pip_install = Some(true);
        let merged = merge_config(file, &common_args(&[])).expect("merges");

        let error = merged.path_spec().resolve().expect_err("planted");

        assert!(
            matches!(
                &error,
                CliError::Sandbox(heel::Error::GrantRedirected { .. })
            ),
            "{error:?}"
        );
    }
}
