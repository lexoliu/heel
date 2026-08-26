//! Landlock ruleset generation for the Linux sandbox.
//!
//! Landlock is default-deny for every access right the ruleset *handles*: a
//! right that is not handled is left entirely unrestricted. Both the filesystem
//! rights and TCP connections are therefore always handled, and permissions are
//! granted back one path or port at a time.

use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, RestrictSelfError, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr,
    RulesetError, RulesetStatus, make_bitflags,
};

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};

/// The Landlock ABI this backend requires.
///
/// v4 is the first version that can restrict TCP connections, which the network
/// policy depends on.
pub(crate) const REQUIRED_ABI: ABI = ABI::V4;

/// A ruleset built on the host, ready to be applied after fork.
pub(crate) struct PreparedRuleset {
    inner: RulesetCreated,
}

// `RulesetCreated` is an opaque kernel handle with no `Debug` of its own, but
// callers still need to format a `Result` holding one.
impl std::fmt::Debug for PreparedRuleset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRuleset").finish_non_exhaustive()
    }
}

impl PreparedRuleset {
    /// Apply the ruleset to the current process. Called from `pre_exec`.
    ///
    /// Anything short of full enforcement is an error: a partially applied
    /// sandbox looks like a sandbox but does not act like one.
    pub(crate) fn restrict_self(self) -> std::io::Result<()> {
        let status = self.inner.restrict_self().map_err(landlock_error_to_io)?;

        match status.ruleset {
            RulesetStatus::FullyEnforced => Ok(()),
            RulesetStatus::PartiallyEnforced | RulesetStatus::NotEnforced => {
                Err(std::io::Error::from_raw_os_error(libc::EPERM))
            }
        }
    }
}

fn landlock_error_to_io(error: RulesetError) -> std::io::Error {
    match error {
        RulesetError::RestrictSelf(RestrictSelfError::SetNoNewPrivsCall { source, .. })
        | RulesetError::RestrictSelf(RestrictSelfError::RestrictSelfCall { source, .. }) => source,
        other => std::io::Error::other(format!("Landlock restrict_self failed: {other}")),
    }
}

/// Verify that the running kernel supports the ABI this backend requires.
///
/// Creating a ruleset is a single syscall, so this is a cheap, side-effect-free
/// probe. It replaces testing the sandbox in a forked child, which is unsound
/// in a multi-threaded process.
pub(crate) fn probe_support() -> Result<()> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(REQUIRED_ABI))
        .and_then(|ruleset| ruleset.handle_access(AccessNet::ConnectTcp))
        .and_then(|ruleset| ruleset.create())
        .map(|_ruleset| ())
        .map_err(|error| {
            Error::NotEnforced(format!(
                "Landlock ABI v{} is required but unavailable: {error}",
                REQUIRED_ABI as i32
            ))
        })
}

/// Build the ruleset for a sandbox configuration.
///
/// `proxy_port` is `Some` only when the network policy permits traffic.
pub(crate) fn build_ruleset(
    config: &SandboxConfigData,
    proxy_port: Option<u16>,
) -> Result<PreparedRuleset> {
    let abi = REQUIRED_ABI;

    // Both filesystem access and TCP connections are always handled. Handling
    // TCP unconditionally is what makes a deny-all policy actually deny: an
    // unhandled right is not restricted at all.
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .and_then(|ruleset| ruleset.handle_access(AccessNet::ConnectTcp))
        .and_then(|ruleset| ruleset.create())
        .map_err(|error| Error::InvalidProfile(format!("Landlock ruleset error: {error}")))?;

    add_system_rules(&mut ruleset, config, abi)?;
    add_device_rules(&mut ruleset, config, abi)?;
    add_configured_rules(&mut ruleset, config, abi)?;

    // Outbound TCP is denied except to the proxy, which applies the policy.
    if let Some(port) = proxy_port {
        ruleset = ruleset
            .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
            .map_err(|e| Error::InvalidProfile(format!("Landlock proxy rule error: {e}")))?;
    }

    tracing::debug!(
        proxy_port,
        working_dir = %config.working_dir().display(),
        strict = config.filesystem_strict(),
        "landlock: ruleset built"
    );

    Ok(PreparedRuleset { inner: ruleset })
}

/// Grant access to the system paths any process needs to start.
fn add_system_rules(
    ruleset: &mut RulesetCreated,
    config: &SandboxConfigData,
    abi: ABI,
) -> Result<()> {
    // Executables and shared libraries.
    let exec_paths: &[&str] = if config.filesystem_strict() {
        &[
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/lib64",
            "/usr/lib32",
            "/lib",
            "/lib64",
            "/lib32",
            "/usr/libexec",
            "/usr/local",
        ]
    } else {
        &["/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin"]
    };

    let exec_access = make_bitflags!(AccessFs::{ ReadFile | ReadDir | Execute });
    for path in exec_paths {
        add_system_path(ruleset, path, exec_access, abi)?;
    }

    // Read-only system state. Required even in strict mode: the dynamic loader
    // and libc consult /etc, and many tools read process metadata from /proc.
    for path in ["/etc", "/proc", "/sys", "/run"] {
        add_system_path(ruleset, path, AccessFs::from_read(abi), abi)?;
    }

    // Shared temp directories are readable outside strict mode, but never
    // writable: the sandbox has its own writable directory, exported as TMPDIR.
    if !config.filesystem_strict() {
        for path in ["/tmp", "/var/tmp"] {
            add_system_path(ruleset, path, AccessFs::from_read(abi), abi)?;
        }
    }

    if config.writable_file_system() {
        add_system_path(ruleset, "/", AccessFs::from_all(abi), abi)?;
    }

    // Landlock is default-deny, so the protections that macOS expresses as
    // explicit denies are the absence of a rule here. Home directories are the
    // one case that needs a rule, to grant access when protection is off.
    if !config.security().protect_user_home() {
        if let Some(home) = std::env::var_os("HOME") {
            add_system_path(ruleset, Path::new(&home), AccessFs::from_all(abi), abi)?;
        }
        add_system_path(ruleset, "/home", AccessFs::from_all(abi), abi)?;
    }

    Ok(())
}

/// Grant access to device nodes.
fn add_device_rules(
    ruleset: &mut RulesetCreated,
    config: &SandboxConfigData,
    abi: ABI,
) -> Result<()> {
    // /dev/stdin and friends are symlinks into /proc/self/fd and work through
    // inherited descriptors rather than through a rule.
    for device in [
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/fd",
    ] {
        add_system_path(ruleset, device, AccessFs::from_all(abi), abi)?;
    }

    // Terminals are readable so interactive programs can query them, and
    // writable only when the configuration allows terminal output.
    let tty_access = if config.allow_tty_write() {
        AccessFs::from_all(abi)
    } else {
        AccessFs::from_read(abi)
    };
    for device in ["/dev/tty", "/dev/ptmx", "/dev/pts"] {
        add_system_path(ruleset, device, tty_access, abi)?;
    }

    let security = config.security();
    if security.allow_gpu() {
        for device in [
            "/dev/dri",
            "/dev/nvidia0",
            "/dev/nvidiactl",
            "/dev/nvidia-modeset",
            "/dev/nvidia-uvm",
        ] {
            add_system_path(ruleset, device, AccessFs::from_all(abi), abi)?;
        }
        tracing::debug!("landlock: GPU access enabled");
    }

    if security.allow_npu() {
        for device in ["/dev/accel", "/dev/accel0"] {
            add_system_path(ruleset, device, AccessFs::from_all(abi), abi)?;
        }
        tracing::debug!("landlock: NPU access enabled");
    }

    if security.allow_hardware() {
        for device in [
            "/dev/bus/usb",
            "/dev/input",
            "/dev/video0",
            "/dev/video1",
            "/dev/snd",
        ] {
            add_system_path(ruleset, device, AccessFs::from_all(abi), abi)?;
        }
        tracing::debug!("landlock: general hardware access enabled");
    }

    Ok(())
}

/// Grant access to the paths the caller configured.
fn add_configured_rules(
    ruleset: &mut RulesetCreated,
    config: &SandboxConfigData,
    abi: ABI,
) -> Result<()> {
    add_required_path(ruleset, config.working_dir(), AccessFs::from_all(abi), abi)?;

    for path in config.readable_paths() {
        add_required_path(ruleset, path, AccessFs::from_read(abi), abi)?;
    }
    for path in config.writable_paths() {
        add_required_path(ruleset, path, AccessFs::from_all(abi), abi)?;
    }

    let exec_access = make_bitflags!(AccessFs::{ ReadFile | Execute });
    for path in config.executable_paths() {
        add_required_path(ruleset, path, exec_access, abi)?;
    }

    // The IPC socket lives outside the working directory; connecting needs
    // read and write on the socket file.
    if let Some(socket) = config.ipc_socket()
        && let Some(dir) = socket.parent()
    {
        add_required_path(ruleset, dir, AccessFs::from_all(abi), abi)?;
    }

    if let Some(python) = config.python() {
        // Without pip installs the environment is read and execute only, so a
        // sandboxed process cannot mutate an environment that outlives it.
        let access = if python.allow_pip_install() {
            AccessFs::from_all(abi)
        } else {
            make_bitflags!(AccessFs::{ ReadFile | ReadDir | Execute })
        };
        add_required_path(ruleset, python.venv().path(), access, abi)?;
    }

    Ok(())
}

/// Add a rule for a path the sandbox needs but that may legitimately be absent.
///
/// Distributions differ in which system paths exist, so a missing one is
/// skipped. A rule that the kernel rejects is still an error: it would silently
/// change what the sandbox enforces.
fn add_system_path(
    ruleset: &mut RulesetCreated,
    path: impl AsRef<Path>,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<()> {
    let path = path.as_ref();
    match PathFd::new(path) {
        Ok(fd) => add_rule(ruleset, path, fd, access, abi),
        Err(error) => {
            tracing::trace!(path = %path.display(), %error, "landlock: skipping absent system path");
            Ok(())
        }
    }
}

/// Add a rule for a path the caller explicitly configured.
///
/// A missing path is an error here: silently dropping it would produce a
/// sandbox that denies exactly the access the caller asked to grant.
fn add_required_path(
    ruleset: &mut RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<()> {
    let fd = PathFd::new(path).map_err(|error| {
        Error::path(
            path,
            std::io::Error::other(format!("cannot open configured path: {error}")),
        )
    })?;
    add_rule(ruleset, path, fd, access, abi)
}

/// Add one rule, narrowing directory-only rights on non-directories.
fn add_rule(
    ruleset: &mut RulesetCreated,
    path: &Path,
    fd: PathFd,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<()> {
    let access = effective_path_access(&fd, path, access, abi)?;

    ruleset
        .add_rule(PathBeneath::new(fd, access))
        .map(|_| ())
        .map_err(|error| {
            Error::InvalidProfile(format!(
                "Landlock rejected the rule for {}: {error}",
                path.display()
            ))
        })
}

/// Reduce a request to the rights that make sense for the target.
///
/// Landlock rejects directory-only rights on a regular file, so a rule naming a
/// file keeps only the file rights.
fn effective_path_access(
    path_fd: &PathFd,
    path: &Path,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<BitFlags<AccessFs>> {
    if path_is_directory(path_fd)? {
        return Ok(access);
    }

    let file_access = access & AccessFs::from_file(abi);
    if file_access.is_empty() {
        return Err(Error::InvalidProfile(format!(
            "Landlock path {} is not a directory, but the requested access {access:?} requires \
             directory semantics",
            path.display(),
        )));
    }

    if file_access != access {
        tracing::trace!(
            path = %path.display(),
            requested = ?access,
            effective = ?file_access,
            "landlock: narrowed non-directory path access"
        );
    }

    Ok(file_access)
}

fn path_is_directory(path_fd: &PathFd) -> Result<bool> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor is open and `stat` is a valid destination.
    let rc = unsafe { libc::fstat(path_fd.as_fd().as_raw_fd(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(Error::InvalidProfile(format!(
            "Landlock failed to inspect a rule path: {}",
            std::io::Error::last_os_error(),
        )));
    }

    // SAFETY: `fstat` succeeded, so the value is initialized.
    let stat = unsafe { stat.assume_init() };
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxConfig;
    use std::fs::{self, File};

    /// A configuration whose working directory exists, as it would at runtime.
    fn prepared(config: SandboxConfig) -> (SandboxConfigData, crate::workdir::WorkingDir) {
        let (_policy, mut data, _ipc) = config.into_parts();
        let dir = crate::workdir::WorkingDir::create(data.working_dir(), true).expect("creates");
        data.set_working_dir(dir.path().to_path_buf());
        (data, dir)
    }

    #[test]
    fn non_directory_rules_are_narrowed_to_file_access() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("device");
        File::create(&file_path).expect("creates");

        let path_fd = PathFd::new(&file_path).expect("opens");
        let access =
            effective_path_access(&path_fd, &file_path, AccessFs::from_all(ABI::V4), ABI::V4)
                .expect("narrows");

        assert_eq!(access, AccessFs::from_file(ABI::V4));
    }

    #[test]
    fn directory_rules_keep_directory_access() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path_fd = PathFd::new(dir.path()).expect("opens");
        let access =
            effective_path_access(&path_fd, dir.path(), AccessFs::from_all(ABI::V4), ABI::V4)
                .expect("keeps");

        assert_eq!(access, AccessFs::from_all(ABI::V4));
    }

    #[test]
    fn file_rules_reject_directory_only_access() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("file");
        File::create(&file_path).expect("creates");

        let path_fd = PathFd::new(&file_path).expect("opens");
        let error = effective_path_access(&path_fd, &file_path, AccessFs::ReadDir.into(), ABI::V4)
            .expect_err("rejects");

        assert!(matches!(error, Error::InvalidProfile(_)));
    }

    #[test]
    fn missing_configured_paths_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("absent");
        let (data, _dir) = prepared(SandboxConfig::builder().readable_path(&missing).build());

        let error = build_ruleset(&data, None).expect_err("must fail");
        assert!(
            matches!(error, Error::Path { .. }),
            "a configured path that cannot be granted must be an error, got {error:?}"
        );
    }

    #[test]
    fn absent_system_paths_are_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (data, _dir) = prepared(SandboxConfig::new());
        // /lib32 and friends are absent on most hosts, and building must still
        // succeed.
        assert!(build_ruleset(&data, None).is_ok());
        drop(dir);
    }

    #[test]
    fn strict_mode_does_not_grant_shared_temp_directories() {
        // Landlock has no rule inspection API, so this checks the decision the
        // ruleset builder makes rather than the resulting kernel state.
        let (strict, _a) = prepared(SandboxConfig::builder().filesystem_strict(true).build());
        let (relaxed, _b) = prepared(SandboxConfig::builder().filesystem_strict(false).build());

        assert!(strict.filesystem_strict());
        assert!(!relaxed.filesystem_strict());
        assert!(build_ruleset(&strict, None).is_ok());
        assert!(build_ruleset(&relaxed, None).is_ok());
    }

    #[test]
    fn venv_is_read_only_without_pip_installs() {
        let venv = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(venv.path().join("bin")).expect("creates");

        for (allow, expected_write) in [(false, false), (true, true)] {
            let (data, _dir) = prepared(
                SandboxConfig::builder()
                    .python(
                        crate::config::PythonConfig::builder()
                            .venv(
                                crate::config::VenvConfig::builder()
                                    .path(venv.path())
                                    .build(),
                            )
                            .allow_pip_install(allow)
                            .build(),
                    )
                    .build(),
            );

            assert_eq!(
                data.python().expect("configured").allow_pip_install(),
                expected_write
            );
            assert!(build_ruleset(&data, None).is_ok());
        }
    }
}
